using System;

namespace Org.BouncyCastle.Bcpg
{

    public class Crc24
    {

        #region Data

        private const Int32 Crc24Init   = 0x0b704ce;
        private const Int32 Crc24Poly   = 0x1864cfb;
        private       Int32 CurrentCRC  = Crc24Init;

        #endregion

        #region Properties
        public Int32 Value
        {
            get
            {
                return CurrentCRC;
            }
        }

        #endregion

        #region Constructor(s)

        public Crc24()
        { }

        #endregion


        #region Update(Value)

        public void Update(Int32 Value)
        {

            CurrentCRC ^= Value << 16;

            for (var i = 0; i < 8; i++)
            {

                CurrentCRC <<= 1;

                if ((CurrentCRC & 0x1000000) != 0)
                    CurrentCRC ^= Crc24Poly;

            }

        }

        #endregion

        #region Reset()

        public void Reset()
        {
            CurrentCRC = Crc24Init;
        }

        #endregion

    }

}
