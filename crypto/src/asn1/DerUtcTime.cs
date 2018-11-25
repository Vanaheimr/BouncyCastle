using System;
using System.Globalization;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{

    /// <summary>
    /// UTC time object.
    /// </summary>
    public class DerUtcTime : Asn1Object
    {

        private readonly String time;


        /// <summary>
        /// The correct format for this is YYMMDDHHMMSSZ (it used to be that seconds were
        /// never encoded. When you're creating one of these objects from scratch, that's
        /// what you want to use, otherwise we'll try to deal with whatever Gets read from
        /// the input stream... (this is why the input format is different from the GetTime()
        /// method output).
        /// </summary>
        /// <param name="time">The time string.</param>
        public DerUtcTime(String time)
        {

            this.time = time ?? throw new ArgumentNullException("time");

            try
            {
                ToDateTime();
            }
            catch (FormatException e)
            {
                throw new ArgumentException("invalid date string: " + e.Message);
            }

        }

        /// <summary>
        /// Base constructor from a DateTime object.
        /// </summary>
        /// <param name="time"></param>
        public DerUtcTime(DateTime time)
        {
            this.time = time.ToString("yyMMddHHmmss") + "Z";
        }

        internal DerUtcTime(Byte[] bytes)
        {

            // explicitly convert to characters
            this.time = Strings.FromAsciiByteArray(bytes);

        }

        //        public DateTime ToDateTime()
        //        {
        //            string tm = this.AdjustedTimeString;
        //
        //            return new DateTime(
        //                Int16.Parse(tm.Substring(0, 4)),
        //                Int16.Parse(tm.Substring(4, 2)),
        //                Int16.Parse(tm.Substring(6, 2)),
        //                Int16.Parse(tm.Substring(8, 2)),
        //                Int16.Parse(tm.Substring(10, 2)),
        //                Int16.Parse(tm.Substring(12, 2)));
        //        }








        /// <summary>
        /// Return an UTC Time from the passed in object.
        /// </summary>
        /// <param name="obj">An object.</param>
        public static DerUtcTime GetInstance(Object obj)
        {

            if (obj == null || obj is DerUtcTime)
                return (DerUtcTime)obj;

            throw new ArgumentException("Illegal object in GetInstance: " + obj.GetType().Name);

        }

        /// <summary>
        /// Return an UTC Time from a tagged object.
        /// </summary>
        /// <param name="obj">The tagged object holding the object we want.</param>
        /// <param name="isExplicit">Explicitly true if the object is meant to be explicitly tagged, false otherwise.</param>
        public static DerUtcTime GetInstance(Asn1TaggedObject obj,
                                             Boolean isExplicit)
        {

            var o = obj.GetObject();

            if (isExplicit || o is DerUtcTime)
                return GetInstance(o);

            return new DerUtcTime(((Asn1OctetString)o).GetOctets());

        }

        /// <summary>
        /// Return the time as a date based on whatever a 2 digit year will return. For
        /// standardised processing use ToAdjustedDateTime().
        /// </summary>
        /// <returns></returns>
        public DateTime ToDateTime()
            => ParseDateString(TimeString, @"yyMMddHHmmss'GMT'zzz");

        /// <summary>
        /// Return the time as an adjusted date in the range of 1950 - 2049.
        /// </summary>
        /// <returns></returns>
        public DateTime ToAdjustedDateTime()
            => ParseDateString(AdjustedTimeString, @"yyyyMMddHHmmss'GMT'zzz");


        private DateTime ParseDateString(String  dateStr,
                                         String  formatStr)
        {

            var dt = DateTime.ParseExact(dateStr,
                                         formatStr,
                                         DateTimeFormatInfo.InvariantInfo);

            return dt.ToUniversalTime();

        }

        /// <summary>
        /// Return the time - always in the form of YYMMDDhhmmssGMT(+hh:mm|-hh:mm).
        /// </summary>
        /// <remarks>
        /// <p>
        /// Normally in a certificate we would expect "Z" rather than "GMT",
        /// however adding the "GMT" means we can just use:
        /// <pre>
        ///     dateF = new SimpleDateFormat("yyMMddHHmmssz");
        /// </pre>
        /// To read in the time and Get a date which is compatible with our local
        /// time zone.</p>
        /// <p>
        /// <b>Note:</b> In some cases, due to the local date processing, this
        /// may lead to unexpected results. If you want to stick the normal
        /// convention of 1950 to 2049 use the GetAdjustedTime() method.</p>
        /// </remarks>
        public String TimeString
        {
            get
            {

                // standardise the format.
                if (time.IndexOf('-') < 0 && time.IndexOf('+') < 0)
                {

                    if (time.Length == 11)
                        return time.Substring(0, 10) + "00GMT+00:00";

                    else
                        return time.Substring(0, 12) + "GMT+00:00";

                }
                else
                {
                    int index = time.IndexOf('-');
                    if (index < 0)
                        index = time.IndexOf('+');

                    string d = time;

                    if (index == time.Length - 3)
                        d += "00";

                    if (index == 10)
                        return d.Substring(0, 10) + "00GMT" + d.Substring(10, 3) + ":" + d.Substring(13, 2);

                    else
                        return d.Substring(0, 12) + "GMT" + d.Substring(12, 3) + ":" +  d.Substring(15, 2);

                }

            }
        }

        [Obsolete("Use 'AdjustedTimeString' property instead")]
        public String AdjustedTime
            => AdjustedTimeString;

        /// <summary>
        /// Return a time string as an adjusted date with a 4 digit year.
        /// This goes in the range of 1950 - 2049.
        /// </summary>
        public String AdjustedTimeString
        {
            get
            {

                String d = TimeString;
                String c = d[0] < '5' ? "20" : "19";

                return c + d;

            }
        }

        private Byte[] GetOctets()
            => Strings.ToAsciiByteArray(time);

        internal override void Encode(DerOutputStream derOut)
        {
            derOut.WriteEncoded(Asn1Tags.UtcTime, GetOctets());
        }

        protected override Boolean Asn1Equals(Asn1Object asn1Object)
        {

            if (!(asn1Object is DerUtcTime derUtcTime))
                return false;

            return time.Equals(derUtcTime?.time);

        }

        protected override Int32 Asn1GetHashCode()
            => time.GetHashCode();

        public override String ToString()
            => time;

    }

}
