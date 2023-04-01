using IPSExtractor;
using Mono.Options;
using System;

internal class Program
{
    public static bool ShowHelp { get; set; }
    public static string InputPath { get; set; }
    public static string OutputPath { get; set; }

    private static void Main(string[] args)
    {
        var options = new OptionSet {
            { "i|input=", "Input Path", i => InputPath = i },
            { "o|output=", "Output Path", i => OutputPath = i },
            { "h|help", "show help", h => ShowHelp = h != null }
        };

        try
        {
            options.Parse(args);
            if (ShowHelp)
            {
                Console.WriteLine("IPS Extractor by EqUiNoX.");
                Console.WriteLine();
                Console.WriteLine("Usage: Repackinator [options]+");
                Console.WriteLine();
                options.WriteOptionDescriptions(Console.Out);
                return;
            }

            var input = Path.GetFullPath(InputPath);
            if (!Directory.Exists(input))
            {
                throw new OptionException("Input is not a valid directory.", "input");
            }

            var output = Path.GetFullPath(OutputPath);
            if (!Directory.Exists(output))
            {
                Directory.CreateDirectory(output);
            }

            var ipsFiles = Directory.GetFiles(input, "*.ips");
            foreach (var ipsFile in ipsFiles)
            {
                IPSTool.ExtractIPS(ipsFile, output);
            }

            Console.WriteLine("Completed.");

        }
        catch (OptionException e)
        {
            Console.Write("IPSExtractor by EqUiNoX: ");
            Console.WriteLine(e.Message);
            Console.WriteLine("Try `IPSExtractor --help' for more information.");
        }
    }
}