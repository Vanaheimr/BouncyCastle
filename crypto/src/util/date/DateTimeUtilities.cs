using System;

namespace Org.BouncyCastle.Utilities.Date
{

    public class DateTimeUtilities
    {

        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1);


        /// <summary>
        /// Return the number of milliseconds since the Unix epoch (1 Jan., 1970 UTC) for a given DateTime value.
        /// </summary>
        /// <param name="dateTime">A UTC DateTime value not before epoch.</param>
        /// <returns>Number of whole milliseconds after epoch.</returns>
        /// <exception cref="ArgumentException">'dateTime' is before epoch.</exception>
        public static UInt64 DateTimeToUnixMs(DateTime dateTime)
        {

            if (dateTime.CompareTo(UnixEpoch) < 0)
                throw new ArgumentException("DateTime value may not be before the epoch", "dateTime");

            return (UInt64) ((dateTime.Ticks - UnixEpoch.Ticks) / TimeSpan.TicksPerMillisecond);

        }

        /// <summary>
        /// Create a DateTime value from the number of milliseconds since the Unix epoch (1 Jan., 1970 UTC).
        /// </summary>
        /// <param name="unixMs">Number of milliseconds since the epoch.</param>
        /// <returns>A UTC DateTime value</returns>
        public static DateTime UnixMsToDateTime(UInt64 unixMs)
        {
            return new DateTime(((Int64) unixMs) * TimeSpan.TicksPerMillisecond + UnixEpoch.Ticks);
        }

        /// <summary>
        /// Return the current number of milliseconds since the Unix epoch (1 Jan., 1970 UTC).
        /// </summary>
        public static UInt64 CurrentUnixMs()
        {
            return DateTimeToUnixMs(DateTime.UtcNow);
        }

    }

}
