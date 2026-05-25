using System;
using System.IO;

public class BridgeHarness
{
    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: BridgeHarness <assembly>");
            return 2;
        }

        string[] inlineArgs = new string[args.Length - 1];
        Array.Copy(args, 1, inlineArgs, 0, inlineArgs.Length);

        string encoded = InlineRunner.Execute(File.ReadAllBytes(args[0]), inlineArgs);
        Console.WriteLine(encoded);
        return encoded != null && encoded.StartsWith("BBR1\n", StringComparison.Ordinal) ? 0 : 1;
    }
}
