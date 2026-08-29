// Copyright 2025 ISP RAS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////

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
        try {
            Console.WriteLine(0);

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

            var input2 = new StringReader(yml);
            
            var parser = new Parser(input2);  

            parser.Consume<StreamStart>();

            var input3 = new StringReader(yml); 
            yaml.Load(input3);       
                      
        }
        catch (YamlException ex) { 
            Console.WriteLine(ex.Message);
        }
    }
}
