using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MeshCentralRouter
{
    public struct ExeData
    {
        public string arch;
        public ushort optionalHeaderSize;
        public uint optionalHeaderSizeAddress;
        public uint CheckSumPos;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUnInitializedData;
        public uint CertificateTableAddress;
        public uint CertificateTableSize;
        public uint CertificateTableSizePos;
        public uint rvaStartAddress;
        public uint rvaCount;
        public string certificate;
        public uint certificateDwLength;
    }
    public struct FileOpts
    {
        public string platform;
        public string destinationFile;
        public string sourceFile;
        public string msh;
        public ExeData? peinfo;
        public bool randomPolicy;
    }
    public static class DataUpdaterStub
    {
        static Guid exeJavaScriptGuid = new Guid("B996015880544A19B7F7E9BE44914C18");
        static Guid exeMeshPolicyGuid = new Guid("B996015880544A19B7F7E9BE44914C19");
        static Guid exeNullPolicyGuid = new Guid("B996015880544A19B7F7E9BE44914C20");
        private class RawBytes
        {
            internal byte[] bytes;

            public int Length { get
                {
                    return bytes.Length;
                }
                private set { } }

            public RawBytes(int size)
            {
                this.bytes = new byte[size];
            }
            public RawBytes(byte[] bytes)
            {
                this.bytes = bytes;
            }

            /// <summary>
            /// This function reads out a single ushort (2-byte unsigned integer) at provided offset. The byte array must have a length of 2 or more
            /// </summary>
            /// <param name="offset">The offset at which to read the ushort from in the byte array</param>
            /// <returns>A single ushort (2-byte unsigned integer) read from the byte array as Little Endian</returns>
            public ushort ReadUInt16LE(int offset = 0)
            {
                if (Length > offset)
                {
                    byte[] vi = new byte[2];
                    for (int i = 0; i < vi.Length; i++)
                    {
                        vi[i] = bytes[offset + i];
                    }
                    return BitConverter.ToUInt16(vi, 0); // Apparently BitConverter Assumes LittleEndian
                }
                else
                {
                    throw new System.ArgumentOutOfRangeException("Out of bounds exception");
                }
            }
            /// <summary>
            /// This function reads out a single ushort (2-byte unsigned integer) at provided offset. The byte array must have a length of 2 or more
            /// </summary>
            /// <param name="offset">The offset at which to read the ushort from in the byte array</param>
            /// <returns>A single ushort (2-byte unsigned integer) read from the byte array as Big Endian</returns>
            public ushort ReadUInt16BE(int offset = 0)
            {
                if (Length > offset)
                {
                    byte[] vi = new byte[2];
                    for (int i = 0; i < vi.Length; i++)
                    {
                        vi[i] = bytes[offset + i];
                    }
                    Array.Reverse(vi);
                    return BitConverter.ToUInt16(vi, 0);
                }
                else
                {
                    throw new System.ArgumentOutOfRangeException("Out of bounds exception");
                }
            }
            /// <summary>
            /// This function reads out a single uint (4-byte unsigned integer) at provided offset. The byte array must have a length of 4 or more
            /// </summary>
            /// <param name="offset">The offset at which to read the uint from in the byte array</param>
            /// <returns>A single ushort (4-byte unsigned integer) read from the byte array as Little Endian</returns>

            public uint ReadUInt32LE(int offset = 0)
            {
                if (Length - 3 > offset)
                {
                    byte[] vi = new byte[4];
                    for (int i = 0; i < vi.Length; i++)
                    {
                        vi[i] = bytes[offset + i];
                    }
                    return BitConverter.ToUInt32(vi, 0);
                }
                else
                {
                    throw new System.ArgumentOutOfRangeException("Out of bounds exception");
                }
            }
            /// <summary>
            /// This function reads out a single uint (4-byte unsigned integer) at provided offset. The byte array must have a length of 4 or more
            /// </summary>
            /// <param name="offset">The offset at which to read the uint from in the byte array</param>
            /// <returns>A single uint (4-byte unsigned integer) read from the byte array as Big Endian</returns>
            public uint ReadUInt32BE(int offset = 0)
            {
                if (Length - 3 > offset)
                {
                    byte[] vi = new byte[4];
                    for (int i = 0; i < vi.Length; i++)
                    {
                        vi[i] = bytes[offset + i];
                    }
                    Array.Reverse(vi);
                    return BitConverter.ToUInt32(vi, 0);
                }
                else
                {
                    throw new System.ArgumentOutOfRangeException("Out of bounds exception");
                }
            }

            internal void writeUInt32BE(object length, int v)
            {
                throw new NotImplementedException();
            }
        }

        public static string strExeFilePath = System.Reflection.Assembly.GetExecutingAssembly().Location;

        public static void streamExeWithMeshPolicy(FileOpts options) {
            // Check all inputs
            if (options.platform == null) { throw new System.Exception("platform not specified"); }
            if (options.destinationFile == null) { throw new System.Exception("destination stream/file was not specified"); }
            if (options.sourceFile == null) { throw new System.Exception("source file not specified"); }
            if (options.msh == null) { throw new System.Exception("msh content not specified"); }

            //create destinationStream
            BinaryWriter destinationWriter = new BinaryWriter(File.OpenRead(exePath));

            // If a Windows binary, parse it if not already parsed
            if ((options.platform == "win32") && (options.peinfo == null)) { options.peinfo = ParseWindowsExecutable(options.sourceFile); }

            // If unsigned Windows or Linux, we merge at the end with the GUID and no padding.
            if ((options.platform == "win32" && options.peinfo.CertificateTableAddress == 0) || options.platform != "win32") {
                // This is not a signed binary, so we can just send over the EXE then the MSH
                FileStream file = File.OpenRead(options.sourceFile);
                RawBytes sourceBytes = new RawBytes(file.Length);
                file.Read(sourceBytes.bytes, 0, file.Length);
                destinationWriter.BaseStream.Write(source,0,file.Length);
                options.destinationS.sourceStream = require('fs').createReadStream(options.sourceFile, { flags: 'r' });
                options.destinationStream.sourceStream.options = options;
                options.destinationStream.sourceStream.on('end', function () {
                    // Once the binary is streamed, write the msh + length + guid in that order.
                    options.destinationStream.write(options.msh); // MSH
                    RawBytes sz = new RawBytes(4);
                    sz.writeUInt32BE(options.msh.Length, 0);
                    options.destinationStream.write(sz); // Length in small endian
                    options.destinationStream.end(Buffer.from((options.randomPolicy === true) ? exeNullPolicyGuid : exeMeshPolicyGuid, 'hex'));  // Guid
                });
                // Pipe the entire source binary without ending the stream.
                options.destinationStream.sourceStream.pipe(options.destinationStream, { end: false });
            } else if (options.platform == 'win32' && options.peinfo.CertificateTableAddress != 0) {
                // Read up to the certificate table size and stream that out
                options.destinationStream.sourceStream = require('fs').createReadStream(options.sourceFile, { flags: 'r', start: 0, end: options.peinfo.CertificateTableSizePos - 1 });
                options.destinationStream.sourceStream.mshPadding = (8 - ((options.peinfo.certificateDwLength + options.msh.length + 20) % 8)) % 8; // Compute the padding with quad-align
                options.destinationStream.sourceStream.CertificateTableSize = (options.peinfo.CertificateTableSize + options.msh.length + 20 + options.destinationStream.sourceStream.mshPadding); // Add to the certificate table size
                options.destinationStream.sourceStream.certificateDwLength = (options.peinfo.certificateDwLength + options.msh.length + 20 + options.destinationStream.sourceStream.mshPadding); // Add to the certificate size
                options.destinationStream.sourceStream.options = options;

                options.destinationStream.sourceStream.on('end', function () {
                    // We sent up to the CertificateTableSize, now we need to send the updated certificate table size
                    var sz = Buffer.alloc(4);
                    sz.writeUInt32LE(options.peinfo.CertificateTableSize, 0);
                    this.options.destinationStream.write(sz); // New cert table size

                    // Stream everything up to the start of the certificate table entry
                    var source2 = require('fs').createReadStream(options.sourceFile, { flags: 'r', start: this.options.peinfo.CertificateTableSizePos + 4, end: options.peinfo.CertificateTableAddress - 1 });
                    source2.options = this.options;
                    source2.mshPadding = this.mshPadding;
                    source2.certificateDwLength = this.certificateDwLength;
                    source2.on('end', function () {
                        // We've sent up to the Certificate DWLength, which we need to update
                        var sz = Buffer.alloc(4);
                        sz.writeUInt32LE(certificateDwLength, 0);
                        this.options.destinationStream.write(sz); // New certificate length

                        // Stream the entire binary until the end
                        var source3 = require('fs').createReadStream(options.sourceFile, { flags: 'r', start: this.options.peinfo.CertificateTableAddress + 4 });
                        source3.options = options;
                        source3.mshPadding = mshPadding;
                        source3.on('end', function () {
                            // We've sent the entire binary... Now send: Padding + MSH + MSHLength + GUID
                            if (this.mshPadding > 0) { this.options.destinationStream.write(Buffer.alloc(this.mshPadding)); } // Padding
                            this.options.destinationStream.write(this.options.msh); // MSH content
                            var sz = Buffer.alloc(4);
                            sz.writeUInt32BE(this.options.msh.length, 0);
                            this.options.destinationStream.write(sz); // MSH Length, small-endian
                            this.options.destinationStream.end(Buffer.from((this.options.randomPolicy === true) ? exeNullPolicyGuid : exeMeshPolicyGuid, 'hex')); // Guid
                        });
                        source3.pipe(this.options.destinationStream, { end: false });
                        this.options.sourceStream = source3;
                    });
                    source2.pipe(this.options.destinationStream, { end: false });
                    this.options.destinationStream.sourceStream = source2;
                });
                options.destinationStream.sourceStream.pipe(options.destinationStream, { end: false });
            }
        };

        public static ExeData ParseWindowsExecutable(string exePath)
        {
            BinaryReader stream = new BinaryReader(File.OpenRead(exePath));
            int bytesRead;
            int ioffset;
            ExeData data = new ExeData();
            RawBytes dosHeader = new RawBytes(64);
            RawBytes ntHeader = new RawBytes(24);

            //bytesRead = new byte[64];
            bytesRead = stream.Read(dosHeader.bytes, 0, 64);
            //Console.WriteLine(dosHeader.ReadUInt16LE(0));
            if (dosHeader.ReadUInt16LE(0) != 0x5a4d) throw new System.Exception("Unknown Binary type");

            // cut header
            //string strDosHeader = BitConverter.ToString(dosHeader).Replace("-","");
            //strDosHeader = strDosHeader.Substring(strDosHeader.Length - 4);
            //Console.WriteLine(strDosHeader);
            ioffset = (int)dosHeader.ReadUInt32LE(60);
            stream.BaseStream.Seek(ioffset, SeekOrigin.Begin);
            bytesRead = stream.Read(ntHeader.bytes, 0, ntHeader.Length);
            if (ntHeader.ReadUInt32BE(0) != 0x50450000) throw new System.Exception("Not PE file");
            Console.WriteLine(ntHeader.ReadUInt16LE(4).ToString("X"));

            switch (ntHeader.ReadUInt16LE(4))
            {
                case 0x014c: // 32-bit
                    data.arch = "x32";
                    break;
                case 0x8664: // 64-bit
                    data.arch = "x64";
                    break;
                default: // unknown
                    data.arch = null;
                    break;
            }

            data.optionalHeaderSize = ntHeader.ReadUInt16LE(20);
            data.optionalHeaderSizeAddress = dosHeader.ReadUInt32LE(60) + 20;

            // Read the optional header
            RawBytes optHeader = new RawBytes(ntHeader.ReadUInt16LE(20));

            ioffset = (int)dosHeader.ReadUInt32LE(60) + 24;
            stream.BaseStream.Seek(ioffset, SeekOrigin.Begin);
            bytesRead = stream.Read(optHeader.bytes, 0, optHeader.Length);

            data.CheckSumPos = dosHeader.ReadUInt32LE(60) + 24 + 64;
            data.SizeOfCode = optHeader.ReadUInt32LE(4);
            data.SizeOfInitializedData = optHeader.ReadUInt32LE(8);
            data.SizeOfUnInitializedData = optHeader.ReadUInt32LE(12);

            uint numRVA;
            switch (optHeader.ReadUInt16LE(0))
            {
                case 0x10b: // 32 bit binary
                    numRVA = optHeader.ReadUInt32LE(92);
                    data.CertificateTableAddress = optHeader.ReadUInt32LE(128);
                    data.CertificateTableSize = optHeader.ReadUInt32LE(132);
                    data.CertificateTableSizePos = dosHeader.ReadUInt32LE(60) + 24 + 132;
                    data.rvaStartAddress = dosHeader.ReadUInt32LE(60) + 24 + 96;
                    break;
                case 0x20b: // 64 bit binary
                    numRVA = optHeader.ReadUInt32LE(108);
                    data.CertificateTableAddress = optHeader.ReadUInt32LE(144);
                    data.CertificateTableSize = optHeader.ReadUInt32LE(148);
                    data.CertificateTableSizePos = dosHeader.ReadUInt32LE(60) + 24 + 148;
                    data.rvaStartAddress = dosHeader.ReadUInt32LE(60) + 24 + 112;
                    break;
                default:
                    throw new System.Exception("Unknown Value found for Optional Magic: " + ntHeader.ReadUInt16LE(24).ToString("X"));
            }
            data.rvaCount = numRVA;

            if (data.CertificateTableAddress != 0)
            {
                // Read the authenticode certificate, only one cert (only the first entry)
                RawBytes hdr = new RawBytes(8);
                stream.BaseStream.Seek(data.CertificateTableAddress, SeekOrigin.Begin);
                stream.Read(hdr.bytes, 0, hdr.Length);
                RawBytes charCertificate = new RawBytes((int)hdr.ReadUInt32LE(0));
                stream.BaseStream.Seek(data.CertificateTableAddress + hdr.Length, SeekOrigin.Begin);
                stream.Read(charCertificate.bytes, 0, charCertificate.Length);
                data.certificate = Convert.ToBase64String(charCertificate.bytes);
                data.certificateDwLength = hdr.ReadUInt32LE(0);
                //Console.WriteLine(data.certificate);
            }
            // cut header
            return data;
        }
    }
}
