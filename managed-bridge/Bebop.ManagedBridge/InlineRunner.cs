using System;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

public class InlineRunner
{
    private static readonly object ConsoleLock = new object();

    public static string Execute(byte[] assemblyBytes, string[] args)
    {
        lock (ConsoleLock)
        {
            try
            {
                return EncodeResult(ExecuteTargetAssembly(assemblyBytes ?? new byte[0], args ?? new string[0]));
            }
            catch (Exception ex)
            {
                return EncodeResult(new InlineExecutionResult
                {
                    ExitCode = -1,
                    Exception = ex.ToString()
                });
            }
        }
    }

    public static string EncodeResult(InlineExecutionResult result)
    {
        return "BBR1\n"
            + result.ExitCode.ToString(CultureInfo.InvariantCulture) + "\n"
            + Convert.ToBase64String(Encoding.UTF8.GetBytes(result.Stdout ?? string.Empty)) + "\n"
            + Convert.ToBase64String(Encoding.UTF8.GetBytes(result.Stderr ?? string.Empty)) + "\n"
            + Convert.ToBase64String(Encoding.UTF8.GetBytes(result.Exception ?? string.Empty));
    }

    private static InlineExecutionResult ExecuteTargetAssembly(byte[] assemblyBytes, string[] args)
    {
        InlineExecutionResult result = new InlineExecutionResult();
        StringWriter stdout = new StringWriter(CultureInfo.InvariantCulture);
        StringWriter stderr = new StringWriter(CultureInfo.InvariantCulture);
        TextWriter originalOut = Console.Out;
        TextWriter originalError = Console.Error;

        try
        {
            Console.SetOut(stdout);
            Console.SetError(stderr);

            Assembly assembly = Assembly.Load(assemblyBytes ?? new byte[0]);
            MethodInfo entryPoint = assembly.EntryPoint;
            if (entryPoint == null)
            {
                throw new MissingMethodException("Assembly does not have an entry point.");
            }

            ParameterInfo[] parameters = entryPoint.GetParameters();
            object invokeResult;

            if (parameters.Length == 0)
            {
                invokeResult = entryPoint.Invoke(null, null);
            }
            else if (parameters.Length == 1 && parameters[0].ParameterType == typeof(string[]))
            {
                invokeResult = entryPoint.Invoke(null, new object[] { args ?? new string[0] });
            }
            else
            {
                throw new NotSupportedException("Unsupported entrypoint. Supported: Main() or Main(string[] args).");
            }

            result.ExitCode = ExtractExitCode(invokeResult);
        }
        catch (TargetInvocationException ex)
        {
            result.ExitCode = -1;
            result.Exception = ex.InnerException != null ? ex.InnerException.ToString() : ex.ToString();
        }
        catch (Exception ex)
        {
            result.ExitCode = -1;
            result.Exception = ex.ToString();
        }
        finally
        {
            try { Console.Out.Flush(); } catch { }
            try { Console.Error.Flush(); } catch { }

            result.Stdout = stdout.ToString() ?? string.Empty;
            result.Stderr = stderr.ToString() ?? string.Empty;
            Console.SetOut(originalOut);
            Console.SetError(originalError);
            stdout.Dispose();
            stderr.Dispose();
        }

        return result;
    }

    private static int ExtractExitCode(object value)
    {
        if (value is int)
        {
            return (int)value;
        }

        Task task = value as Task;
        if (task != null)
        {
            task.GetAwaiter().GetResult();

            PropertyInfo resultProperty = task.GetType().GetProperty("Result", BindingFlags.Public | BindingFlags.Instance);
            if (resultProperty != null && resultProperty.PropertyType == typeof(int))
            {
                return (int)resultProperty.GetValue(task, null);
            }
        }

        return 0;
    }

}

[Serializable]
public sealed class InlineExecutionResult
{
    public int ExitCode { get; set; }

    public string Stdout { get; set; } = string.Empty;

    public string Stderr { get; set; } = string.Empty;

    public string Exception { get; set; } = string.Empty;
}
