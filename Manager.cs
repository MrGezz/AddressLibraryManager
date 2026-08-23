using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AddressLibraryManager
{
    public static class Manager
    {
        public static Database CurrentDatabase
        {
            get;
            set;
        }

        public static System.IO.FileInfo CurrentFile
        {
            get;
            set;
        }

        public static uint Modified
        {
            get;
            set;
        }

        /// <summary>
        /// Changes the extension of file.
        /// </summary>
        /// <param name="file">The file.</param>
        /// <param name="extension">The extension.</param>
        /// <returns></returns>
        /// <exception cref="System.ArgumentNullException">file</exception>
        public static System.IO.FileInfo ChangeExtension(System.IO.FileInfo file, string extension)
        {
            if (file == null)
                throw new ArgumentNullException("file");

            int ix = file.Name.LastIndexOf('.');
            if(ix < 0)
            {
                if (string.IsNullOrEmpty(extension))
                    return file;
                return new System.IO.FileInfo(file.FullName + "." + extension);
            }

            string fn = System.IO.Path.Combine(file.DirectoryName, file.Name.Substring(0, ix));
            if (!string.IsNullOrEmpty(extension))
                fn = fn + "." + extension;
            return new System.IO.FileInfo(fn);
        }
    }

    /// <summary>
    /// Database of versions for a game.
    /// </summary>
    public sealed class Database
    {
        /// <summary>
        /// Gets or sets the high vid.
        /// </summary>
        /// <value>
        /// The high vid.
        /// </value>
        public ulong HighVID
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the name of the target module.
        /// </summary>
        /// <value>
        /// The name of the target module.
        /// </value>
        public string TargetModuleName
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the size of the pointer.
        /// </summary>
        /// <value>
        /// The size of the pointer.
        /// </value>
        public int PointerSize
        {
            get;
            set;
        } = 8;

        /// <summary>
        /// Gets or sets the versions.
        /// </summary>
        /// <value>
        /// The versions.
        /// </value>
        public SortedDictionary<Version, Library> Versions
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the names.
        /// </summary>
        /// <value>
        /// The names.
        /// </value>
        public SortedDictionary<ulong, string> Names
        {
            get;
            set;
        }

        /// <summary>
        /// Gets the save version.
        /// </summary>
        /// <value>
        /// The save version.
        /// </value>
        internal static int SaveVersion
        {
            get
            {
                return 2;
            }
        }

        /// <summary>
        /// Saves all.
        /// </summary>
        /// <param name="file">The file.</param>
        /// <param name="mask">The mask.</param>
        public void SaveAll(System.IO.FileInfo file, uint mask = 0xFFFFFFFF)
        {
            if((mask & 1) != 0)
            {
                var offsetFile = Manager.ChangeExtension(file, "relib");
                SaveOffsets(offsetFile);
            }

            if((mask & 2) != 0)
            {
                var nameFile = Manager.ChangeExtension(file, "rename");
                if ((this.Names == null || this.Names.Count == 0) && nameFile.Exists)
                    nameFile.Delete();
                else
                    SaveNames(nameFile);
            }
        }

        /// <summary>
        /// Loads all.
        /// </summary>
        /// <param name="file">The file.</param>
        public void LoadAll(System.IO.FileInfo file)
        {
            this.Clear();

            {
                var offsetFile = Manager.ChangeExtension(file, "relib");
                if(offsetFile.Exists)
                    LoadOffsets(offsetFile);
            }

            {
                var nameFile = Manager.ChangeExtension(file, "rename");
                if (nameFile.Exists)
                    LoadNames(nameFile);
            }
        }

        /// <summary>
        /// Saves the database to specified file.
        /// </summary>
        /// <param name="file">The file.</param>
        public void SaveOffsets(System.IO.FileInfo file)
        {
            using (var stream = file.Create())
            {
                using (var f = new System.IO.BinaryWriter(stream, new UTF8Encoding(false)))
                {
                    f.Write(SaveVersion);

                    f.Write(this.HighVID);
                    f.Write(this.PointerSize);

                    if (this.TargetModuleName != null)
                    {
                        f.Write((byte)1);
                        f.Write(this.TargetModuleName);
                    }
                    else
                        f.Write((byte)0);

                    if (this.Versions != null && this.Versions.Count != 0)
                    {
                        f.Write((int)this.Versions.Count);
                        foreach (var pair in this.Versions)
                            pair.Value.WriteToStream(f);
                    }
                    else
                        f.Write((int)0);
                }
            }
        }

        /// <summary>
        /// Loads the database from specified file.
        /// </summary>
        /// <param name="file">The file.</param>
        /// <returns></returns>
        public void LoadOffsets(System.IO.FileInfo file)
        {
            if (file == null)
                throw new ArgumentNullException("file");
            
            using (var stream = file.OpenRead())
            {
                using (var f = new System.IO.BinaryReader(stream, new UTF8Encoding(false)))
                {
                    int version = f.ReadInt32();
                    if (version < 1 || version > SaveVersion)
                        throw new NotSupportedException("Invalid file version: " + version + "!");

                    this.HighVID = f.ReadUInt64();
                    this.PointerSize = f.ReadInt32();

                    if (f.ReadByte() != 0)
                        this.TargetModuleName = f.ReadString();

                    int c = f.ReadInt32();
                    if(c != 0)
                    {
                        this.Versions = new SortedDictionary<Version, Library>();
                        for(int i = 0; i < c; i++)
                        {
                            var l = new Library();
                            l.ReadFromStream(f, version);
                            this.Versions.Add(l.Version, l);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Saves the database to specified file.
        /// </summary>
        /// <param name="file">The file.</param>
        public void SaveNames(System.IO.FileInfo file)
        {
            using (var stream = file.Create())
            {
                using (var f = new System.IO.StreamWriter(stream, new UTF8Encoding(false)))
                {
                    f.WriteLine(SaveVersion.ToString());

                    if (this.Names != null && this.Names.Count != 0)
                    {
                        foreach (var pair in this.Names)
                        {
                            f.Write(pair.Key.ToString());
                            f.Write(' ');
                            f.Write(pair.Value);
                            f.WriteLine();
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Loads the database from specified file.
        /// </summary>
        /// <param name="file">The file.</param>
        /// <returns></returns>
        public void LoadNames(System.IO.FileInfo file)
        {
            if (file == null)
                throw new ArgumentNullException("file");

            using (var stream = file.OpenRead())
            {
                using (var f = new System.IO.StreamReader(stream, new UTF8Encoding(false)))
                {
                    string verstr = f.ReadLine();
                    int ver;
                    if (!int.TryParse(verstr, System.Globalization.NumberStyles.None, null, out ver))
                        throw new FormatException("Expected version!");

                    var map = new SortedDictionary<ulong, string>();
                    string l;
                    int lnnr = 1;
                    while((l = f.ReadLine()) != null)
                    {
                        lnnr++;

                        if (l.Length == 0 || l[0] == ';' || l[0] == '#')
                            continue;

                        int ix = l.IndexOf(' ');
                        if (ix < 0)
                            throw new FormatException("Line " + lnnr + ": bad format!");

                        ulong k;
                        string v = l.Substring(ix + 1);

                        if (!ulong.TryParse(l.Substring(0, ix), System.Globalization.NumberStyles.None, null, out k))
                            throw new FormatException("Line " + lnnr + ": bad id!");

                        map.Add(k, v);
                    }

                    if (map.Count != 0)
                        this.Names = map;
                }
            }
        }

        /// <summary>
        /// Clears this instance.
        /// </summary>
        public void Clear()
        {
            this.HighVID = 0;
            this.PointerSize = 8;
            this.Names = null;
            this.Versions = null;
            this.TargetModuleName = null;
        }
    }

    /// <summary>
    /// One version library of the game.
    /// </summary>
    public sealed class Library
    {
        /// <summary>
        /// Gets or sets the version.
        /// </summary>
        /// <value>
        /// The version.
        /// </value>
        public Version Version
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the base address.
        /// </summary>
        /// <value>
        /// The base address.
        /// </value>
        public long BaseAddress
        {
            get;
            set;
        } = 0x140000000;

        /// <summary>
        /// Gets or sets the target module name overwrite.
        /// </summary>
        /// <value>
        /// The name of the overwrite target module.
        /// </value>
        public string OverwriteTargetModuleName
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the values.
        /// </summary>
        /// <value>
        /// The values.
        /// </value>
        public SortedDictionary<ulong, uint> Values
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the function hashes.
        /// </summary>
        public SortedDictionary<ulong, ulong> Hashes
        {
            get;
            set;
        }

        /// <summary>
        /// Writes to stream.
        /// </summary>
        /// <param name="f">The writer.</param>
        internal void WriteToStream(System.IO.BinaryWriter f)
        {
            var ls = this.Version.Numbers;
            f.Write(ls.Count);
            foreach (var x in ls)
                f.Write(x);

            if (this.OverwriteTargetModuleName != null)
            {
                f.Write((byte)1);
                f.Write(this.OverwriteTargetModuleName);
            }
            else
                f.Write((byte)0);

            f.Write(this.BaseAddress);

            if (this.Values != null && this.Values.Count != 0)
            {
                f.Write((int)this.Values.Count);
                foreach(var pair in this.Values)
                {
                    f.Write(pair.Key);
                    f.Write(pair.Value);
                }
            }
            else
                f.Write((int)0);

            if (this.Hashes != null && this.Hashes.Count != 0)
            {
                f.Write((int)this.Hashes.Count);
                foreach(var pair in this.Hashes)
                {
                    f.Write(pair.Key);
                    f.Write(pair.Value);
                }
            }
            else
                f.Write((int)0);
        }

        /// <summary>
        /// Reads from stream.
        /// </summary>
        /// <param name="f">The reader.</param>
        /// <param name="version">The version.</param>
        internal void ReadFromStream(System.IO.BinaryReader f, int version)
        {
            {
                int n = f.ReadInt32();
                List<uint> nr = new List<uint>();
                for (int i = 0; i < n; i++)
                    nr.Add(f.ReadUInt32());

                this.Version = new Version(nr.ToArray());
            }

            if (f.ReadByte() != 0)
                this.OverwriteTargetModuleName = f.ReadString();

            this.BaseAddress = f.ReadInt64();

            {
                int c = f.ReadInt32();
                if(c != 0)
                {
                    this.Values = new SortedDictionary<ulong, uint>();
                    for(int i = 0; i < c; i++)
                    {
                        ulong k = f.ReadUInt64();
                        uint v = f.ReadUInt32();
                        this.Values.Add(k, v);
                    }
                }
            }

            if(version >= 2)
            {
                int c = f.ReadInt32();
                if(c != 0)
                {
                    this.Hashes = new SortedDictionary<ulong, ulong>();
                    for(int i = 0; i < c; i++)
                    {
                        ulong k = f.ReadUInt64();
                        ulong v = f.ReadUInt64();
                        this.Hashes.Add(k, v);
                    }
                }
            }
        }

        /// <summary>
        /// Writes the address library.
        /// </summary>
        /// <param name="database">The database.</param>
        /// <param name="file">The file.</param>
        /// <exception cref="System.ArgumentNullException">
        /// database
        /// or
        /// file
        /// </exception>
        public void WriteAddressLibrary(Database database, System.IO.FileInfo file)
        {
            this.WriteAddressLibrary(database, file, AddressLibraryFormatFor(this.Version));
        }

        /// <summary>
        /// Address Library file formats. 1 = Skyrim SE 1.5.x "version-*.bin", 2 = Anniversary Edition "versionlib-*.bin" up to
        /// 1.6.1179 (same packing as 1), 5 = the dense table meh321 introduced with the 1.7.99 library (2026-08-20).
        /// </summary>
        public const int FormatPackedSE = 1;
        public const int FormatPacked = 2;
        public const int FormatDense = 5;
        private const int DenseNameLength = 64;

        /// <summary>
        /// The format meh321 ships for a game version: 1 for 1.5.x, 2 for 1.6.x, 5 from 1.7 on.
        /// </summary>
        /// <param name="version">The game version.</param>
        public static int AddressLibraryFormatFor(Version version)
        {
            var n = version.Numbers;
            uint major = n.Count > 0 ? n[0] : 1;
            uint minor = n.Count > 1 ? n[1] : 0;
            if (major > 1 || (major == 1 && minor >= 7))
                return FormatDense;
            if (major == 1 && minor <= 5)
                return FormatPackedSE;
            return FormatPacked;
        }

        /// <summary>
        /// Gets the file name the loaders look for: version-*.bin for format 1, versionlib-*.bin otherwise.
        /// </summary>
        public string AddressLibraryFileName
        {
            get
            {
                string root = AddressLibraryFormatFor(this.Version) == FormatPackedSE ? "version-" : "versionlib-";
                return root + string.Join("-", this.Version.Numbers) + ".bin";
            }
        }

        /// <summary>
        /// Writes the address library in the given format.
        /// </summary>
        /// <param name="database">The database.</param>
        /// <param name="file">The file.</param>
        /// <param name="format">1, 2 or 5; see <see cref="AddressLibraryFormatFor"/>.</param>
        public void WriteAddressLibrary(Database database, System.IO.FileInfo file, int format)
        {
            if (database == null)
                throw new ArgumentNullException("database");

            if (file == null)
                throw new ArgumentNullException("file");

            if (format == FormatDense)
            {
                this.WriteDenseAddressLibrary(database, file);
                return;
            }

            if (format != FormatPacked && format != FormatPackedSE)
                throw new ArgumentOutOfRangeException("format", "Supported Address Library formats are 1, 2 and 5.");

            using (var stream = file.Create())
            {
                using (var f = new System.IO.BinaryWriter(stream))
                {
                    f.Write((int)format); // File format version.

                    {
                        var ver = this.Version.Numbers.ToList();
                        while (ver.Count < 4)
                            ver.Add(0);
                        while (ver.Count > 4)
                            ver.RemoveAt(ver.Count - 1);

                        foreach (var n in ver)
                            f.Write(n);
                    }

                    {
                        string name = this.OverwriteTargetModuleName;
                        if (name == null)
                            name = database.TargetModuleName;

                        if (name == null)
                            throw new NullReferenceException("TargetModuleName");

                        byte[] enc = Encoding.UTF8.GetBytes(name);
                        f.Write((int)enc.Length);
                        f.Write(enc);
                    }

                    f.Write(database.PointerSize);

                    if (this.Values != null && this.Values.Count != 0)
                    {
                        f.Write((int)this.Values.Count);

                        ulong pvid = 0;
                        ulong poffset = 0;
                        bool hadprev = false;
                        ulong sz = (ulong)database.PointerSize;
                        foreach (var pair in this.Values)
                        {
                            ulong vid = pair.Key;
                            ulong offset = pair.Value;

                            if (!hadprev)
                            {
                                f.Write((byte)0);
                                f.Write(vid);
                                f.Write(offset);
                                hadprev = true;
                                pvid = vid;
                                poffset = offset;
                                continue;
                            }

                            this.WritePackedPair(f, vid, offset, pvid, poffset, sz);
                            pvid = vid;
                            poffset = offset;
                        }
                    }
                    else
                        f.Write((int)0);
                }
            }
        }

        /// <summary>
        /// Writes the packed pair.
        /// </summary>
        /// <param name="w">The writer.</param>
        /// <param name="vid">The vid.</param>
        /// <param name="offset">The offset.</param>
        /// <param name="pvid">The pvid.</param>
        /// <param name="poffset">The poffset.</param>
        private void WritePackedPair(System.IO.BinaryWriter w, ulong vid, ulong offset, ulong pvid, ulong poffset, ulong sz)
        {
            byte low = 0;
            byte high = 0;

            if ((offset % sz) == 0 && (poffset % sz) == 0)
            {
                offset /= sz;
                poffset /= sz;
                high |= 8;
            }

            long vdiff = unchecked((long)vid) - unchecked((long)pvid);
            long odiff = unchecked((long)offset) - unchecked((long)poffset);

            if (vid == pvid + 1)
                low = 1;
            else if (vdiff >= 0 && vdiff <= byte.MaxValue)
                low = 2;
            else if (vdiff < 0 && -vdiff <= byte.MaxValue)
                low = 3;
            else if (vdiff >= 0 && vdiff <= ushort.MaxValue)
                low = 4;
            else if (vdiff < 0 && -vdiff <= ushort.MaxValue)
                low = 5;
            else if (vid <= ushort.MaxValue)
                low = 6;
            else if (vid <= uint.MaxValue)
                low = 7;

            if (offset == poffset + 1)
                high |= 1;
            else if (odiff >= 0 && odiff <= byte.MaxValue)
                high |= 2;
            else if (odiff < 0 && -odiff <= byte.MaxValue)
                high |= 3;
            else if (odiff >= 0 && odiff <= ushort.MaxValue)
                high |= 4;
            else if (odiff < 0 && -odiff <= ushort.MaxValue)
                high |= 5;
            else if (offset <= ushort.MaxValue)
                high |= 6;
            else if (offset <= uint.MaxValue)
                high |= 7;

            byte mask = high;
            mask <<= 4;
            mask |= low;
            w.Write(mask);

            int wsz = 1;
            switch (low)
            {
                case 0: w.Write(vid); wsz += 8; break;
                case 1: break;
                case 2: w.Write((byte)vdiff); wsz++; break;
                case 3: w.Write((byte)(-vdiff)); wsz++; break;
                case 4: w.Write((ushort)vdiff); wsz += 2; break;
                case 5: w.Write((ushort)(-vdiff)); wsz += 2; break;
                case 6: w.Write((ushort)vid); wsz += 2; break;
                case 7: w.Write((uint)vid); wsz += 4; break;
                default:
                    throw new InvalidOperationException();
            }

            switch (high & 7)
            {
                case 0: w.Write(offset); wsz += 8; break;
                case 1: break;
                case 2: w.Write((byte)odiff); wsz++; break;
                case 3: w.Write((byte)(-odiff)); wsz++; break;
                case 4: w.Write((ushort)odiff); wsz += 2; break;
                case 5: w.Write((ushort)(-odiff)); wsz += 2; break;
                case 6: w.Write((ushort)offset); wsz += 2; break;
                case 7: w.Write((uint)offset); wsz += 4; break;
                default:
                    throw new InvalidOperationException();
            }
        }

        /// <summary>
        /// Writes the format 5 library: a 96-byte header followed by one uint32 offset per ID, indexed directly by ID
        /// (offset 0 = unassigned). This is the layout commonlib-shared's REL::IDDB::load_v5 memory-maps.
        /// </summary>
        /// <param name="database">The database.</param>
        /// <param name="file">The file.</param>
        private void WriteDenseAddressLibrary(Database database, System.IO.FileInfo file)
        {
            string name = this.OverwriteTargetModuleName;
            if (name == null)
                name = database.TargetModuleName;

            if (name == null)
                throw new NullReferenceException("TargetModuleName");

            byte[] enc = Encoding.UTF8.GetBytes(name);
            if (enc.Length >= DenseNameLength)
                throw new InvalidOperationException("Target module name does not fit the 64-byte format 5 header: " + name);

            long count = 0;
            if (this.Values != null && this.Values.Count != 0)
            {
                foreach (var pair in this.Values)
                {
                    if (pair.Value == 0)
                        throw new InvalidOperationException("ID " + pair.Key + " has offset 0, which format 5 reserves for unassigned IDs.");
                    if (pair.Key >= int.MaxValue)
                        throw new InvalidOperationException("ID " + pair.Key + " is too large for a format 5 table.");
                }

                count = (long)this.Values.Keys.Max() + 1;
            }

            using (var stream = file.Create())
            {
                using (var f = new System.IO.BinaryWriter(stream))
                {
                    f.Write((int)FormatDense); // File format version.

                    {
                        var ver = this.Version.Numbers.ToList();
                        while (ver.Count < 4)
                            ver.Add(0);
                        while (ver.Count > 4)
                            ver.RemoveAt(ver.Count - 1);

                        foreach (var n in ver)
                            f.Write(n);
                    }

                    var nameField = new byte[DenseNameLength];
                    Array.Copy(enc, nameField, enc.Length);
                    f.Write(nameField);

                    f.Write(database.PointerSize);
                    f.Write((int)0); // Data format; reserved, 0 in every library meh321 has published.
                    f.Write((int)count);

                    var table = new uint[count];
                    if (this.Values != null)
                    {
                        foreach (var pair in this.Values)
                            table[pair.Key] = pair.Value;
                    }

                    var bytes = new byte[count * 4];
                    Buffer.BlockCopy(table, 0, bytes, 0, bytes.Length);
                    f.Write(bytes);
                }
            }
        }

        /// <summary>
        /// Reads a version-*.bin / versionlib-*.bin of format 1, 2 or 5 into a new library (version and values only).
        /// The module name and pointer size from the header come back through the out parameters so the caller can
        /// check them against the database before importing.
        /// </summary>
        /// <param name="file">The file.</param>
        /// <param name="format">The file format that was read.</param>
        /// <param name="moduleName">Target module name from the header.</param>
        /// <param name="pointerSize">Pointer size from the header.</param>
        public static Library ReadAddressLibrary(System.IO.FileInfo file, out int format, out string moduleName, out int pointerSize)
        {
            if (file == null)
                throw new ArgumentNullException("file");

            using (var stream = file.OpenRead())
            {
                using (var f = new System.IO.BinaryReader(stream))
                {
                    format = f.ReadInt32();

                    var lib = new Library();
                    var nums = new uint[4];
                    for (int i = 0; i < 4; i++)
                        nums[i] = f.ReadUInt32();
                    lib.Version = new Version(nums);
                    lib.Values = new SortedDictionary<ulong, uint>();

                    if (format == FormatDense)
                    {
                        var nameField = f.ReadBytes(DenseNameLength);
                        if (nameField.Length != DenseNameLength)
                            throw new FormatException("Truncated format 5 header!");
                        int len = Array.IndexOf(nameField, (byte)0);
                        if (len < 0)
                            len = DenseNameLength;
                        moduleName = Encoding.UTF8.GetString(nameField, 0, len);
                        pointerSize = f.ReadInt32();
                        f.ReadInt32(); // Data format; reserved.
                        int count = f.ReadInt32();
                        if (count < 0)
                            throw new FormatException("Bad format 5 offset count!");

                        var bytes = f.ReadBytes(count * 4);
                        if (bytes.Length != count * 4)
                            throw new FormatException("Truncated format 5 table!");

                        for (int id = 0; id < count; id++)
                        {
                            uint offset = BitConverter.ToUInt32(bytes, id * 4);
                            if (offset != 0)
                                lib.Values.Add((ulong)id, offset);
                        }
                    }
                    else if (format == FormatPacked || format == FormatPackedSE)
                    {
                        int nlen = f.ReadInt32();
                        moduleName = Encoding.UTF8.GetString(f.ReadBytes(nlen));
                        pointerSize = f.ReadInt32();
                        int count = f.ReadInt32();

                        ulong sz = (ulong)pointerSize;
                        ulong pvid = 0;
                        ulong poffset = 0;
                        for (int i = 0; i < count; i++)
                        {
                            byte mask = f.ReadByte();
                            byte low = (byte)(mask & 0xF);
                            byte high = (byte)(mask >> 4);

                            ulong vid;
                            switch (low)
                            {
                                case 0: vid = f.ReadUInt64(); break;
                                case 1: vid = pvid + 1; break;
                                case 2: vid = pvid + f.ReadByte(); break;
                                case 3: vid = pvid - f.ReadByte(); break;
                                case 4: vid = pvid + f.ReadUInt16(); break;
                                case 5: vid = pvid - f.ReadUInt16(); break;
                                case 6: vid = f.ReadUInt16(); break;
                                case 7: vid = f.ReadUInt32(); break;
                                default:
                                    throw new FormatException("Bad ID encoding at pair " + i + "!");
                            }

                            ulong pref = (high & 8) != 0 ? poffset / sz : poffset;
                            ulong offset;
                            switch (high & 7)
                            {
                                case 0: offset = f.ReadUInt64(); break;
                                case 1: offset = pref + 1; break;
                                case 2: offset = pref + f.ReadByte(); break;
                                case 3: offset = pref - f.ReadByte(); break;
                                case 4: offset = pref + f.ReadUInt16(); break;
                                case 5: offset = pref - f.ReadUInt16(); break;
                                case 6: offset = f.ReadUInt16(); break;
                                case 7: offset = f.ReadUInt32(); break;
                                default:
                                    throw new FormatException("Bad offset encoding at pair " + i + "!");
                            }

                            if ((high & 8) != 0)
                                offset *= sz;

                            if (offset > uint.MaxValue)
                                throw new FormatException("Offset of ID " + vid + " does not fit in 32 bits!");

                            lib.Values[vid] = (uint)offset;
                            pvid = vid;
                            poffset = offset;
                        }
                    }
                    else
                        throw new FormatException("Unsupported Address Library format " + format + "! Supported formats are 1, 2 and 5.");

                    if (stream.Position != stream.Length)
                        throw new FormatException("Trailing data after the Address Library!");

                    return lib;
                }
            }
        }
    }

    /// <summary>
    /// Version information.
    /// </summary>
    public struct Version : IComparable, IComparable<Version>, IEquatable<Version>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Version" /> struct.
        /// </summary>
        /// <param name="numbers">The numbers.</param>
        /// <exception cref="System.ArgumentNullException">numbers</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">numbers;The numbers array can't be empty!</exception>
        public Version(params uint[] numbers)
        {
            if (numbers == null)
                throw new ArgumentNullException("numbers");

            if (numbers.Length == 0)
                throw new ArgumentOutOfRangeException("numbers", "The numbers array can't be empty!");

            this._numbers = numbers.ToList();
        }

        /// <summary>
        /// Gets the numbers that make up the version. There can be any amount of numbers here but there will always be at least one number. Most significant number is first, least significant is last.
        /// </summary>
        /// <value>
        /// The numbers.
        /// </value>
        public IReadOnlyList<uint> Numbers
        {
            get
            {
                if (this._numbers != null && this._numbers.Count != 0)
                    return this._numbers;
                return Default;
            }
        }
        private List<uint> _numbers;
        private static readonly uint[] Default = new uint[] { 1 };

        /// <summary>
        /// Tries to parse version from string.
        /// </summary>
        /// <param name="text">The text.</param>
        /// <param name="result">The result.</param>
        /// <returns></returns>
        public static bool TryParse(string text, out Version result)
        {
            if (!string.IsNullOrEmpty(text))
            {
                List<uint> ls = null;
                var spl = text.Split(new[] { '.' }, StringSplitOptions.None);
                for (int i = 0; i < spl.Length; i++)
                {
                    var l = spl[i];
                    uint u = 0;
                    if (string.IsNullOrEmpty(l) || !uint.TryParse(l, out u))
                    {
                        ls = null;
                        break;
                    }

                    if (ls == null)
                        ls = new List<uint>(Math.Min(16, spl.Length));

                    ls.Add(u);
                }

                if (ls != null && ls.Count != 0)
                {
                    result = new Version()
                    {
                        _numbers = ls
                    };
                    return true;
                }
            }

            result = new Version();
            return false;
        }

        #region Object overloads

        /// <summary>
        /// Determines whether the specified <see cref="System.Object" />, is equal to this instance.
        /// </summary>
        /// <param name="obj">The <see cref="System.Object" /> to compare with this instance.</param>
        /// <returns>
        ///   <c>true</c> if the specified <see cref="System.Object" /> is equal to this instance; otherwise, <c>false</c>.
        /// </returns>
        public override bool Equals(object obj)
        {
            if (!(obj is Version))
                return false;

            var nthis = this.Numbers;
            var noth = ((Version)obj).Numbers;
            int highest = Math.Max(nthis.Count, noth.Count);
            for (int i = 0; i < highest; i++)
            {
                uint mthis = i >= nthis.Count ? 0 : nthis[i];
                uint moth = i >= noth.Count ? 0 : noth[i];

                if (mthis != moth)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>
        /// A <see cref="System.String" /> that represents this instance.
        /// </returns>
        public override string ToString()
        {
            return string.Join(".", this.Numbers);
        }

        /// <summary>
        /// Returns a hash code for this instance.
        /// </summary>
        /// <returns>
        /// A hash code for this instance, suitable for use in hashing algorithms and data structures like a hash table. 
        /// </returns>
        public override int GetHashCode()
        {
            var nthis = this.Numbers;
            int max = nthis.Count;

            for (int i = nthis.Count - 1; i >= 0; i--)
            {
                uint nr = nthis[i];
                if (nr != 0)
                    break;

                max = i;
            }

            uint hc = 0;
            for (int i = 0; i < max; i++)
            {
                hc = unchecked(hc * 17);
                hc += nthis[i];
            }
            return unchecked((int)hc);
        }

        #endregion

        #region IComparable interface

        /// <summary>
        /// Compares the current instance with another object of the same type and returns an integer that indicates whether the current instance precedes, follows, or occurs in the same position in the sort order as the other object.
        /// </summary>
        /// <param name="obj">An object to compare with this instance.</param>
        /// <returns>
        /// A value that indicates the relative order of the objects being compared. The return value has these meanings: Value Meaning Less than zero This instance precedes <paramref name="obj" /> in the sort order. Zero This instance occurs in the same position in the sort order as <paramref name="obj" />. Greater than zero This instance follows <paramref name="obj" /> in the sort order.
        /// </returns>
        public int CompareTo(object obj)
        {
            if (!(obj is Version))
                return 0;

            return this.CompareTo((Version)obj);
        }

        /// <summary>
        /// Compares the current object with another object of the same type.
        /// </summary>
        /// <param name="other">An object to compare with this object.</param>
        /// <returns>
        /// A value that indicates the relative order of the objects being compared. The return value has the following meanings: Value Meaning Less than zero This object is less than the <paramref name="other" /> parameter.Zero This object is equal to <paramref name="other" />. Greater than zero This object is greater than <paramref name="other" />.
        /// </returns>
        public int CompareTo(Version other)
        {
            var nthis = this.Numbers;
            var noth = other.Numbers;
            int max = Math.Max(nthis.Count, noth.Count);
            for (int i = 0; i < max; i++)
            {
                uint mthis = i >= nthis.Count ? 0 : nthis[i];
                uint moth = i >= noth.Count ? 0 : noth[i];

                int c = mthis.CompareTo(moth);
                if (c != 0)
                    return c;
            }

            return 0;
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <param name="other">An object to compare with this object.</param>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other" /> parameter; otherwise, false.
        /// </returns>
        public bool Equals(Version other)
        {
            return this.CompareTo(other) == 0;
        }

        #endregion
    }
}
