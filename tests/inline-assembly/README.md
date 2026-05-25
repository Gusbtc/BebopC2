# Inline Assembly Test Fixtures

These C# programs are small fixture assemblies for validating BebopC2 `inline-assembly` behavior in v1.5.0.

## Fixtures

- `MainNoArgs.cs`: `Main()` writes `Bebop inline OK`
- `MainArgs.cs`: `Main(string[] args)` echoes arguments joined by `|`
- `StdErr.cs`: writes `err-test` to `stderr`
- `Throws.cs`: throws `Exception("boom")`
- `LargeOutput.cs`: emits enough output to trigger truncation safeguards

## Build examples

Build with .NET Framework compiler on Windows:

```powershell
mkdir bin
csc /nologo /target:exe /out:bin\MainNoArgs.exe MainNoArgs.cs
csc /nologo /target:exe /out:bin\MainArgs.exe MainArgs.cs
csc /nologo /target:exe /out:bin\StdErr.exe StdErr.cs
csc /nologo /target:exe /out:bin\Throws.exe Throws.cs
csc /nologo /target:exe /out:bin\LargeOutput.exe LargeOutput.cs
```

Build with included MSBuild wrapper if preferred:

```powershell
msbuild InlineAssemblyFixtures.proj /t:Build /p:OutDir=bin\
```

## Suggested checklist

1. `inline-assembly --mode bridge MainNoArgs.exe`
2. `inline-assembly --mode bridge MainArgs.exe "C:\Program Files\x" --name "Spike Spiegel"`
3. `inline-assembly --mode bridge StdErr.exe`
4. `inline-assembly --mode bridge Throws.exe`
5. `inline-assembly --mode bridge LargeOutput.exe`
6. `inline-assembly --mode direct MainNoArgs.exe`
7. Remove `Bebop.ManagedBridge.dll`, then run `--mode auto`
8. Remove `Bebop.ManagedBridge.dll`, then run `--mode bridge` and confirm task rejection
9. Run two inline tasks back to back on same Windows beacon and confirm both succeed

## Expected observations

- `MainNoArgs.exe`: `stdout` contains `Bebop inline OK`
- `MainArgs.exe`: `stdout` contains `C:\Program Files\x|--name|Spike Spiegel`, exit code `7`
- `StdErr.exe`: `stderr` contains `err-test`
- `Throws.exe`: `exception` contains `boom`, beacon stays alive
- `LargeOutput.exe`: result is truncated, beacon stays alive
- `--mode direct`: diagnostics warn about best-effort native capture

Use only in authorized lab or assessment environments.
