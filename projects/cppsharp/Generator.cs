using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using CppSharp.AST;
using CppSharp.AST.Extensions;
using CppSharp.Generators;
using CppSharp.Generators.CSharp;
using CppSharp.Passes;
using CppSharp.Types;
using CppSharp.Utils;
using SharpFuzz;
using Attribute = CppSharp.AST.Attribute;
using Type = CppSharp.AST.Type;

namespace CppSharp.Tests
{
    public class CSharpTestsGenerator : ILibrary
    {
        readonly string name;
        readonly GeneratorKind kind;

        public CSharpTestsGenerator(string name, GeneratorKind kind)
        {
            this.name = name;
            this.kind = kind;
        }

        public void Setup(Driver driver)
        {
            var options = driver.Options;
            options.GeneratorKind = kind;
            options.OutputDir = "/CppSharp/build/gen/CSharp";
            options.Quiet = true;
            options.GenerateDebugOutput = true;
            options.CheckSymbols = true;
            var testModule = options.AddModule(name);

            Diagnostics.Message("");
            Diagnostics.Message("Generating bindings for {0} ({1})",
                testModule.LibraryName, options.GeneratorKind.ToString());

            //Console.WriteLine("here");
            //var path = Path.GetFullPath("/CppSharp/tests/dotnet/CSharp");
            var path = Path.GetFullPath("/corpus_gen");
            testModule.IncludeDirs.Add(path);
            testModule.LibraryDirs.Add(options.OutputDir);
            testModule.Libraries.Add($"{name}.Native");

            var files = Directory.EnumerateFiles(path, "*.h", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                var includeDir = Path.GetDirectoryName(file);

                if (!testModule.IncludeDirs.Contains(includeDir))
                    testModule.IncludeDirs.Add(includeDir);

                testModule.Headers.Add(Path.GetFileName(file));
            }

            driver.ParserOptions.UnityBuild = true;
            driver.ParserOptions.AddSupportedFunctionTemplates("FunctionTemplate");

            driver.Options.GenerateFreeStandingFunctionsClassName = t => t.FileNameWithoutExtension + "Cool";
        }

        public void SetupPasses(Driver driver)
        {
            driver.Context.TranslationUnitPasses.AddPass(new TestAttributesPass());
            var moveFunctionToClassPass = driver.Context.TranslationUnitPasses.FindPass<MoveFunctionToClassPass>();
            driver.Context.TranslationUnitPasses.RemovePass(moveFunctionToClassPass);
            driver.Context.TranslationUnitPasses.AddPass(new FunctionToInstanceMethodPass());
            driver.Context.TranslationUnitPasses.AddPass(new MoveFunctionToClassPass());
            driver.Options.MarshalCharAsManagedChar = true;
            driver.Options.GenerateDefaultValuesForArguments = true;
            driver.Options.GenerateClassTemplates = true;

            var disableNativeToManaged = new ClassGenerationOptions { GenerateNativeToManaged = false };
            driver.Options.GetClassGenerationOptions = e => 
            {
                return e.Name == "ClassWithoutNativeToManaged" ? disableNativeToManaged : null;
            };
        }

        public void Preprocess(Driver driver, ASTContext ctx)
        {
        }

        public void Postprocess(Driver driver, ASTContext ctx)
        {
        }

        public static void Main(string[] args)
        {
            Fuzzer.OutOfProcess.Run(stream =>
            {
                ConsoleDriver.Run(new CSharpTestsGenerator("CSharp", GeneratorKind.CSharp));
            });
        }
    }

    public class TestAttributesPass : TranslationUnitPass
    {
        public override bool VisitFunctionDecl(Function function)
        {
            if (AlreadyVisited(function) || function.Name != "obsolete")
                return false;

            var attribute = new Attribute
            {
                Type = typeof(ObsoleteAttribute),
                Value = string.Format("\"{0} is obsolete.\"", function.Name)
            };

            function.Attributes.Add(attribute);

            return base.VisitFunctionDecl(function);
        }
    }
}
