using SharpFuzz;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using System.IO;
using System.Text;
using YamlDotNet.RepresentationModel;

public class Program
{
	public static void Main(string[] args)
	{
		Fuzzer.OutOfProcess.Run(stream =>
		{
            try {
                    string yml = File.ReadAllText(args[0]);
                    var input = new StringReader(yml);

                    var yaml = new YamlStream();
                    var deserializer = new DeserializerBuilder()
                        .WithNamingConvention(CamelCaseNamingConvention.Instance)
                        .Build();
                    var serializer = new SerializerBuilder()
                        .JsonCompatible()
                        .Build();

                    var doc = deserializer.Deserialize(input);
                    var json = serializer.Serialize(doc);
                    var parser = new Parser(input);
                    parser.Consume<StreamStart>();
                    yaml.Load(input);
            }
            catch (YamlException) { }
            catch (System.InvalidOperationException) { }
            catch (System.ArgumentNullException) { }
            catch (System.ArgumentException) { }
            catch (Exception ex) {
                Console.WriteLine( "\nMessage ---\n{0}", ex.Message );
                Console.WriteLine(ex.GetType().ToString());
                //throw;
            }
		});
	}
}
