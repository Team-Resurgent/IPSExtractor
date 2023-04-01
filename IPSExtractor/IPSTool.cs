using System.Text;

namespace IPSExtractor
{
    public static class IPSTool
    {

        public static void ExtractIPS(string inputFile, string outputPath)
        {
            Console.WriteLine($"Processing '{Path.GetFileName(inputFile)}'");

            if (Directory.Exists(outputPath) == false)
            {
                Directory.CreateDirectory(outputPath);
            }

            using var memoryStream = new MemoryStream(File.ReadAllBytes(inputFile));
            using var binaryReader = new BinaryReader(memoryStream);

            var header = binaryReader.ReadBytes(5);
            var magic = Encoding.ASCII.GetString(header);
            if (magic != "PATCH")
            {
                Console.WriteLine("Errir: Invalid header.");
                return;
            }

            const int IPSEOF = 0x454f46;

            var infoFilePath = Path.Combine(outputPath, Path.GetFileNameWithoutExtension(inputFile) + "_info.txt");
            if (File.Exists(infoFilePath))
            {
                File.Delete(infoFilePath);
            }

            using var infoFile = File.CreateText(infoFilePath);

            var patchIndex = 1;
            while (memoryStream.Position != memoryStream.Length)
            {
                var offsetBytes = binaryReader.ReadBytes(3);
                var offset = (offsetBytes[0] << 16) | (offsetBytes[1] << 8) | offsetBytes[2];
                if (offset == IPSEOF)
                {
                    break;
                }

                var sizeByes = binaryReader.ReadBytes(2);
                var size = (sizeByes[0] << 8) | sizeByes[1];

                byte[] data;
                bool rleEncoded = false;
                if (size == 0)
                {
                    sizeByes = binaryReader.ReadBytes(2);
                    size = (sizeByes[0] << 8) | sizeByes[1];
                    data = new byte[size];
                    var rleByte = binaryReader.ReadByte();
                    for (var i = 0; i < size; i++)
                    {
                        data[i] = rleByte;
                    }
                    rleEncoded = true;
                }
                else
                {
                    data = binaryReader.ReadBytes(size);
                }

                var binaryFile = Path.GetFileNameWithoutExtension(inputFile) + $"_patch{patchIndex++}.bin";
                var binaryFilePath = Path.Combine(outputPath, binaryFile);
                if (File.Exists(binaryFilePath))
                {
                    File.Delete(binaryFilePath);
                }

                var asmFile = Path.GetFileNameWithoutExtension(inputFile) + $"_patch{patchIndex++}.asm";
                var asmFilePath = Path.Combine(outputPath, asmFile);
                if (File.Exists(asmFilePath))
                {
                    File.Delete(asmFilePath);
                }
                File.WriteAllBytes(binaryFilePath, data);

                var stringWriter = new StringWriter();
                var disasm = new SharpDisasm.Disassembler(data, SharpDisasm.ArchitectureMode.x86_32, 0, true);
                foreach (var insn in disasm.Disassemble())
                {
                    stringWriter.WriteLine(insn.ToString());
                }
                File.WriteAllText(asmFilePath, stringWriter.ToString());

                Console.WriteLine($"Offset = {offset}, RLE = {rleEncoded}, Size = {size}, File = {binaryFile}");

                infoFile.WriteLine("{0}|{1}|{2}|{3}", offset, rleEncoded, size, binaryFile);
            }

            Console.WriteLine("Processed.");
        }

    }
}
