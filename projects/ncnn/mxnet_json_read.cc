// Tencent is pleased to support the open source community by making ncnn available.
//
// Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
//
// Licensed under the BSD 3-Clause License (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
// https://opensource.org/licenses/BSD-3-Clause
//
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

#include <limits.h>
#include <map>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#include "fuzzer_temp_file.h"

class MXNetParam;
class MXNetNode
{
public:
    bool has_attr(const char* key) const;
    bool is_attr_scalar(const char* key) const;

    class AttrProxy
    {
        MXNetNode const* _n;
        const char* const _key;

    public:
        AttrProxy(MXNetNode const* n, const char* key)
            : _n(n), _key(key)
        {
        }
        operator int() const
        {
            return _n->attr_i(_key);
        }
        operator float() const
        {
            return _n->attr_f(_key);
        }
        operator std::string() const
        {
            return _n->attr_s(_key);
        }
        operator std::vector<int>() const
        {
            return _n->attr_ai(_key);
        }
        operator std::vector<float>() const
        {
            return _n->attr_af(_key);
        }
    };

    AttrProxy attr(const char* key) const
    {
        return AttrProxy(this, key);
    }

    int attr_i(const char* key) const;
    float attr_f(const char* key) const;
    std::string attr_s(const char* key) const;
    std::vector<int> attr_ai(const char* key) const;
    std::vector<float> attr_af(const char* key) const;

public:
    bool is_weight() const;
    bool has_weight(int i) const;
    std::vector<float> weight(int i, int init_len = 0) const;

    std::vector<MXNetNode>* nodes;   // reference
    std::vector<MXNetParam>* params; // reference

public:
    std::string op;
    std::string name;
    int output_size;
    std::map<std::string, std::string> attrs;
    std::vector<int> inputs;
    std::vector<int> subinputs;
    std::vector<int> weights;
};

class MXNetParam
{
public:
    std::string name;
    std::vector<float> data;
    std::string init;
};

bool MXNetNode::has_attr(const char* key) const
{
    const std::map<std::string, std::string>::const_iterator it = attrs.find(key);
    return it != attrs.end();
}

bool MXNetNode::is_attr_scalar(const char* key) const
{
    const std::map<std::string, std::string>::const_iterator it = attrs.find(key);
    if (it == attrs.end())
        return false;

    if (it->second.empty())
        return false;

    return it->second[0] != '(';
}

int MXNetNode::attr_i(const char* key) const
{
    const std::map<std::string, std::string>::const_iterator it = attrs.find(key);
    if (it == attrs.end())
        return 0;

    if (it->second == "False")
        return 0;

    if (it->second == "True")
        return 1;

    int i = 0;
    int nscan = sscanf(it->second.c_str(), "%d", &i);
    if (nscan != 1)
        return 0;

    return i;
}

float MXNetNode::attr_f(const char* key) const
{
    const std::map<std::string, std::string>::const_iterator it = attrs.find(key);
    if (it == attrs.end())
        return 0.f;

    float f = 0;
    int nscan = sscanf(it->second.c_str(), "%f", &f);
    if (nscan != 1)
        return 0.f;

    return f;
}

std::string MXNetNode::attr_s(const char* key) const
{
    const std::map<std::string, std::string>::const_iterator it = attrs.find(key);
    if (it == attrs.end())
        return std::string();

    return it->second;
}

std::vector<int> MXNetNode::attr_ai(const char* key) const
{
    const std::map<std::string, std::string>::const_iterator it = attrs.find(key);
    if (it == attrs.end())
        return std::vector<int>();

    // (1,2,3)
    std::vector<int> list;

    if (is_attr_scalar(key))
    {
        list.push_back(attr_i(key));
        return list;
    }

    int i = 0;
    int c = 0;
    int nconsumed = 0;
    int nscan = sscanf(it->second.c_str() + c, "%*[\\[(,]%d%n", &i, &nconsumed);
    if (nscan != 1)
    {
        // (None
        if (strncmp(it->second.c_str() + c, "(None", 5) == 0)
        {
            i = -233;
            nconsumed = 5;
            nscan = 1;
        }
    }
    while (nscan == 1)
    {
        list.push_back(i);
        //         fprintf(stderr, "%d\n", i);

        i = 0;
        c += nconsumed;
        nscan = sscanf(it->second.c_str() + c, "%*[(,]%d%n", &i, &nconsumed);
        if (nscan != 1)
        {
            // , None
            if (strncmp(it->second.c_str() + c, ", None", 6) == 0)
            {
                i = -233;
                nconsumed = 6;
                nscan = 1;
            }
        }
    }

    return list;
}

std::vector<float> MXNetNode::attr_af(const char* key) const
{
    const std::map<std::string, std::string>::const_iterator it = attrs.find(key);
    if (it == attrs.end())
        return std::vector<float>();

    // (0.1,0.2,0.3)
    std::vector<float> list;

    if (is_attr_scalar(key))
    {
        list.push_back(attr_f(key));
        return list;
    }

    float i = 0.f;
    int c = 0;
    int nconsumed = 0;
    int nscan = sscanf(it->second.c_str() + c, "%*[(,]%f%n", &i, &nconsumed);
    while (nscan == 1)
    {
        list.push_back(i);
        //         fprintf(stderr, "%f\n", i);

        i = 0.f;
        c += nconsumed;
        nscan = sscanf(it->second.c_str() + c, "%*[(,]%f%n", &i, &nconsumed);
    }

    return list;
}

bool MXNetNode::is_weight() const
{
    for (int i = 0; i < (int)(*params).size(); i++)
    {
        const MXNetParam& p = (*params)[i];
        if (p.name == name)
            return true;
    }

    return false;
}

bool MXNetNode::has_weight(int i) const
{
    if (i < 0 || i >= (int)weights.size())
        return false;

    const std::string& node_name = (*nodes)[weights[i]].name;

    for (int j = 0; j < (int)(*params).size(); j++)
    {
        const MXNetParam& p = (*params)[j];
        if (p.name == node_name)
            return true;
    }

    return false;
}

std::vector<float> MXNetNode::weight(int i, int init_len) const
{
    if (i < 0 || i >= (int)weights.size())
        return std::vector<float>();

    const std::string& node_name = (*nodes)[weights[i]].name;

    for (int j = 0; j < (int)(*params).size(); j++)
    {
        const MXNetParam& p = (*params)[j];
        if (p.name != node_name)
            continue;

        if (!p.data.empty())
            return p.data;

        std::vector<float> data;

        if (!p.init.empty() && init_len != 0)
        {
            if (p.init == "[\\$zero\\$, {}]" || p.init == "[\\\"zero\\\", {}]" || p.init == "zeros")
            {
                data.resize(init_len, 0.f);
            }
            else if (p.init == "[\\$one\\$, {}]" || p.init == "[\\\"one\\\", {}]" || p.init == "ones")
            {
                data.resize(init_len, 1.f);
            }
        }

        return data;
    }

    return std::vector<float>();
}

static void replace_backslash_doublequote_dollar(char* s)
{
    char* a = s;
    char* b = s + 1;
    while (*a && *b)
    {
        if (*a == '\\' && *b == '\"')
        {
            *b = '$';
        }

        a++;
        b++;
    }
}

static void parse_input_list(const char* s, std::vector<int>& inputs, std::vector<int>& subinputs)
{
    inputs.clear();
    subinputs.clear();

    if (memcmp(s, "[]", 2) == 0)
        return;

    int nscan = 0;
    int nconsumed = 0;

    int id;
    int subid;

    int c = 1; // skip leading [
    nscan = sscanf(s + c, "[%d, %d%n", &id, &subid, &nconsumed);
    while (nscan == 2)
    {
        inputs.push_back(id);
        subinputs.push_back(subid);
        //         fprintf(stderr, "%d %d\n", id, subid);

        c += nconsumed;
        nscan = sscanf(s + c, "%*[^[][%d, %d%n", &id, &subid, &nconsumed);
    }
}

static bool read_mxnet_json(const char* jsonpath, std::vector<MXNetNode>& nodes)
{
    FILE* fp = fopen(jsonpath, "rb");
    if (!fp)
    {
        fprintf(stderr, "fopen %s failed\n", jsonpath);
        return false;
    }

    int internal_unknown = 0;
    int internal_underscore = 0;

    char line[1024];

    //{
    char* s = fgets(line, 1024, fp);
    if (!s)
    {
        fprintf(stderr, "fgets %s failed\n", jsonpath);
        return false;
    }

    MXNetNode n;

    bool in_nodes_list = false;
    bool in_node_block = false;
    bool in_attr_block = false;
    bool in_inputs_block = false;
    while (!feof(fp))
    {
        char* t = fgets(line, 1024, fp);
        if (!t)
            break;

        if (in_inputs_block)
        {
            //      ]
            if (memcmp(line, "      ]", 7) == 0)
            {
                in_inputs_block = false;
                continue;
            }

            //        [439, 0, 0],
            int id;
            int subid;
            int nscan = sscanf(line, "        [%d, %d", &id, &subid);
            if (nscan == 2)
            {
                n.inputs.push_back(id);
                n.subinputs.push_back(subid);
                continue;
            }
        }

        if (in_attr_block)
        {
            //      },
            if (memcmp(line, "      }", 7) == 0)
            {
                in_attr_block = false;
                continue;
            }

            // replace \" with \$
            replace_backslash_doublequote_dollar(line);

            //        "kernel": "(7,7)",
            char key[256] = {0};
            char value[256] = {0};
            int nscan = sscanf(line, "        \"%255[^\"]\": \"%255[^\"]\"", key, value);
            if (nscan == 2)
            {
                n.attrs[key] = value;
                //                 fprintf(stderr, "# %s = %s\n", key, value);
                continue;
            }
        }

        if (in_node_block)
        {
            //    },
            if (memcmp(line, "    }", 5) == 0)
            {
                // new node
                if (n.name.empty())
                {
                    // assign default unknown name
                    char unknownname[256];
                    sprintf(unknownname, "unknownncnn_%d", internal_unknown);

                    n.name = unknownname;

                    internal_unknown++;
                }
                if (n.name[0] == '_')
                {
                    // workaround for potential duplicated _plus0
                    char underscorename[256];
                    sprintf(underscorename, "underscorencnn_%d%s", internal_underscore, n.name.c_str());

                    n.name = underscorename;

                    internal_underscore++;
                }
                nodes.push_back(n);

                in_node_block = false;
                continue;
            }

            int nscan;

            //      "op": "Convolution",
            char op[256] = {0};
            nscan = sscanf(line, "      \"op\": \"%255[^\"]\",", op);
            if (nscan == 1)
            {
                n.op = op;
                //                 fprintf(stderr, "op = %s\n", op);
                continue;
            }

            //      "name": "conv0",
            char name[256] = {0};
            nscan = sscanf(line, "      \"name\": \"%255[^\"]\",", name);
            if (nscan == 1)
            {
                n.name = name;
                //                 fprintf(stderr, "name = %s\n", name);
                continue;
            }

            //      "inputs": [
            if (memcmp(line, "      \"inputs\": [\n", 18) == 0)
            {
                in_inputs_block = true;
                continue;
            }

            //      "inputs": []
            char inputs[256] = {0};
            nscan = sscanf(line, "      \"inputs\": %255[^\n]", inputs);
            if (nscan == 1)
            {
                parse_input_list(inputs, n.inputs, n.subinputs);
                //                 fprintf(stderr, "inputs = %s\n", inputs);
                continue;
            }

            //      "param": {},
            if (memcmp(line, "      \"param\": {}", 17) == 0)
            {
                continue;
            }

            // replace \" with \$
            replace_backslash_doublequote_dollar(line);

            //      "attr": {"__init__": "[\"zero\", {}]"},
            char key[256] = {0};
            char value[256] = {0};
            nscan = sscanf(line, "      \"attr\": {\"%255[^\"]\": \"%255[^\"]\"}", key, value);
            if (nscan == 2)
            {
                n.attrs[key] = value;
                //                 fprintf(stderr, "# %s = %s\n", key, value);
                continue;
            }

            //      "attrs": {"__init__": "[\"zero\", {}]"},
            nscan = sscanf(line, "      \"attrs\": {\"%255[^\"]\": \"%255[^\"]\"}", key, value);
            if (nscan == 2)
            {
                n.attrs[key] = value;
                //                 fprintf(stderr, "# %s = %s\n", key, value);
                continue;
            }

            //      "param": {"p": "0.5"},
            nscan = sscanf(line, "      \"param\": {\"%255[^\"]\": \"%255[^\"]\"}", key, value);
            if (nscan == 2)
            {
                n.attrs[key] = value;
                //                 fprintf(stderr, "# %s = %s\n", key, value);
                continue;
            }

            //      "attr": {
            if (memcmp(line, "      \"attr\": {", 15) == 0)
            {
                in_attr_block = true;
                continue;
            }

            //      "attrs": {
            if (memcmp(line, "      \"attrs\": {", 16) == 0)
            {
                in_attr_block = true;
                continue;
            }

            //      "param": {
            if (memcmp(line, "      \"param\": {", 16) == 0)
            {
                in_attr_block = true;
                continue;
            }
        }

        if (in_nodes_list)
        {
            //  ],
            if (memcmp(line, "  ],", 4) == 0)
            {
                in_nodes_list = false;
                // all nodes parsed
                break;
            }

            //    {
            if (memcmp(line, "    {", 5) == 0)
            {
                n = MXNetNode();

                in_node_block = true;
                continue;
            }
        }

        //  "nodes": [
        if (memcmp(line, "  \"nodes\": [", 12) == 0)
        {
            in_nodes_list = true;
            continue;
        }
    }

    fclose(fp);

    return true;
}

static bool read_mxnet_param(const char* parampath, std::vector<MXNetParam>& params)
{
    FILE* fp = fopen(parampath, "rb");
    if (!fp)
    {
        fprintf(stderr, "fopen %s failed\n", parampath);
        return false;
    }

    size_t nread;
    uint64_t header;
    uint64_t reserved;
    nread = fread(&header, sizeof(uint64_t), 1, fp);
    if (nread != 1)
    {
        fprintf(stderr, "read header failed %zd\n", nread);
        return false;
    }
    nread = fread(&reserved, sizeof(uint64_t), 1, fp);
    if (nread != 1)
    {
        fprintf(stderr, "read reserved failed %zd\n", nread);
        return false;
    }

    // NDArray vec

    // each data
    uint64_t data_count;
    nread = fread(&data_count, sizeof(uint64_t), 1, fp);
    if (nread != 1)
    {
        fprintf(stderr, "read data_count failed %zd\n", nread);
        return false;
    }

    //     fprintf(stderr, "data count = %d\n", (int)data_count);

    for (int i = 0; i < (int)data_count; i++)
    {
        uint32_t magic; // 0xF993FAC9
        nread = fread(&magic, sizeof(uint32_t), 1, fp);
        if (nread != 1)
        {
            fprintf(stderr, "read magic failed %zd\n", nread);
            return false;
        }

        // shape
        uint32_t ndim;
        std::vector<int64_t> shape;

        if (magic == 0xF993FAC9)
        {
            int32_t stype;
            nread = fread(&stype, sizeof(int32_t), 1, fp);
            if (nread != 1)
            {
                fprintf(stderr, "read stype failed %zd\n", nread);
                return false;
            }

            nread = fread(&ndim, sizeof(uint32_t), 1, fp);
            if (nread != 1)
            {
                fprintf(stderr, "read ndim failed %zd\n", nread);
                return false;
            }

            shape.resize(ndim);
            nread = fread(&shape[0], ndim * sizeof(int64_t), 1, fp);
            if (nread != 1)
            {
                fprintf(stderr, "read shape failed %zd\n", nread);
                return false;
            }
        }
        else if (magic == 0xF993FAC8)
        {
            nread = fread(&ndim, sizeof(uint32_t), 1, fp);
            if (nread != 1)
            {
                fprintf(stderr, "read ndim failed %zd\n", nread);
                return false;
            }

            shape.resize(ndim);
            nread = fread(&shape[0], ndim * sizeof(int64_t), 1, fp);
            if (nread != 1)
            {
                fprintf(stderr, "read shape failed %zd\n", nread);
                return false;
            }
        }
        else
        {
            ndim = magic;

            shape.resize(ndim);

            std::vector<uint32_t> shape32;
            shape32.resize(ndim);
            nread = fread(&shape32[0], ndim * sizeof(uint32_t), 1, fp);
            if (nread != 1)
            {
                fprintf(stderr, "read shape failed %zd\n", nread);
                return false;
            }

            for (int j = 0; j < (int)ndim; j++)
            {
                shape[j] = shape32[j];
            }
        }

        // context
        int32_t dev_type;
        int32_t dev_id;
        nread = fread(&dev_type, sizeof(int32_t), 1, fp);
        if (nread != 1)
        {
            fprintf(stderr, "read dev_type failed %zd\n", nread);
            return false;
        }
        nread = fread(&dev_id, sizeof(int32_t), 1, fp);
        if (nread != 1)
        {
            fprintf(stderr, "read dev_id failed %zd\n", nread);
            return false;
        }

        int32_t type_flag;
        nread = fread(&type_flag, sizeof(int32_t), 1, fp);
        if (nread != 1)
        {
            fprintf(stderr, "read type_flag failed %zd\n", nread);
            return false;
        }

        // data
        size_t len = 0;
        if (shape.size() == 1) len = shape[0];
        if (shape.size() == 2) len = shape[0] * shape[1];
        if (shape.size() == 3) len = shape[0] * shape[1] * shape[2];
        if (shape.size() == 4) len = shape[0] * shape[1] * shape[2] * shape[3];

        MXNetParam p;

        p.data.resize(len);
        nread = fread(&p.data[0], len * sizeof(float), 1, fp);
        if (nread != 1)
        {
            fprintf(stderr, "read MXNetParam data failed %zd\n", nread);
            return false;
        }

        params.push_back(p);

        //         fprintf(stderr, "%u read\n", len);
    }

    // each name
    uint64_t name_count;
    nread = fread(&name_count, sizeof(uint64_t), 1, fp);
    if (nread != 1)
    {
        fprintf(stderr, "read name_count failed %zd\n", nread);
        return false;
    }

    //     fprintf(stderr, "name count = %d\n", (int)name_count);

    for (int i = 0; i < (int)name_count; i++)
    {
        uint64_t len;
        nread = fread(&len, sizeof(uint64_t), 1, fp);
        if (nread != 1)
        {
            fprintf(stderr, "read name length failed %zd\n", nread);
            return false;
        }

        MXNetParam& p = params[i];

        p.name.resize(len);
        nread = fread((char*)p.name.data(), len, 1, fp);
        if (nread != 1)
        {
            fprintf(stderr, "read MXNetParam name failed %zd\n", nread);
            return false;
        }

        // cut leading arg:
        if (memcmp(p.name.c_str(), "arg:", 4) == 0)
        {
            p.name = std::string(p.name.c_str() + 4);
        }
        if (memcmp(p.name.c_str(), "aux:", 4) == 0)
        {
            p.name = std::string(p.name.c_str() + 4);
        }

        //         fprintf(stderr, "%s read\n", p.name.c_str());
    }

    fclose(fp);

    return true;
}

static void fuse_shufflechannel(std::vector<MXNetNode>& nodes, std::vector<MXNetParam>& params, std::map<size_t, int>& node_reference, std::set<std::string>& blob_names, int& reduced_node_count)
{
    size_t node_count = nodes.size();
    for (size_t i = 0; i < node_count; i++)
    {
        const MXNetNode& n = nodes[i];

        if (n.is_weight())
            continue;

        // ShuffleChannel <= Reshape - SwapAxis - Reshape
        if (n.op == "Reshape")
        {
            if (node_reference.find(i) == node_reference.end() || node_reference[i] != 1)
                continue;

            // "shape": "(0, -4, X, -1, -2)"
            std::vector<int> shape = n.attr("shape");
            if (shape.size() != 5)
                continue;
            if (shape[0] != 0 || shape[1] != -4 || shape[3] != -1 || shape[4] != -2)
                continue;

            if (i + 2 >= node_count)
                continue;

            const MXNetNode& n2 = nodes[i + 1];
            const MXNetNode& n3 = nodes[i + 2];

            if (n2.op != "SwapAxis" || n3.op != "Reshape")
                continue;

            if (node_reference.find(i + 1) == node_reference.end() || node_reference[i + 1] != 1)
                continue;

            // "dim1": "1", "dim2": "2"
            int dim1 = n2.attr("dim1");
            int dim2 = n2.attr("dim2");
            if (dim1 != 1 || dim2 != 2)
                continue;

            // "shape": "(0, -3, -2)"
            std::vector<int> shape3 = n3.attr("shape");
            if (shape3.size() != 3)
                continue;
            if (shape3[0] != 0 || shape3[1] != -3 || shape3[2] != -2)
                continue;

            // reduce
            nodes[i].op = "noop_reducedncnn";
            nodes[i + 1].op = "noop_reducedncnn";

            node_reference.erase(node_reference.find(i));
            node_reference.erase(node_reference.find(i + 1));
            blob_names.erase(n.name);
            blob_names.erase(n2.name);

            MXNetNode new_node;
            new_node.nodes = &nodes;
            new_node.params = &params;
            new_node.op = "ShuffleChannel";
            //             new_node.name = n.name + "_" + n2.name + "_" + n3.name;
            new_node.name = n3.name;
            new_node.output_size = n3.output_size;
            char group[16];
            sprintf(group, "%d", shape[2]);
            new_node.attrs["group"] = group;
            new_node.inputs = n.inputs;
            new_node.subinputs = n.subinputs;

            nodes[i + 2] = new_node;

            reduced_node_count += 2;
            i += 2;
        }
    }
}

static void fuse_hardsigmoid_hardswish(std::vector<MXNetNode>& nodes, std::vector<MXNetParam>& params, std::map<size_t, int>& node_reference, std::set<std::string>& blob_names, int& reduced_node_count)
{
    size_t node_count = nodes.size();
    for (size_t i = 0; i < node_count; i++)
    {
        const MXNetNode& n = nodes[i];

        if (n.is_weight())
            continue;

        if (n.op == "_plus_scalar")
        {
            // HardSigmoid <= _plus_scalar(+3) - clip(0,6) - _div_scalar(/6)
            const MXNetNode& n1 = nodes[i + 1];
            const MXNetNode& n2 = nodes[i + 2];
            const MXNetNode& n3 = nodes[i + 3];

            if ((float)n.attr("scalar") != 3.f)
                continue;

            if (n1.op != "clip" || (float)n1.attr("a_min") != 0.f || (float)n1.attr("a_max") != 6.f)
                continue;

            if (n2.op != "_div_scalar" || (float)n2.attr("scalar") != 6.f)
                continue;

            // reduce
            nodes[i].op = "noop_reducedncnn";
            nodes[i + 1].op = "noop_reducedncnn";

            node_reference.erase(node_reference.find(i));
            node_reference.erase(node_reference.find(i + 1));
            blob_names.erase(n.name);
            blob_names.erase(n1.name);

            if (n3.op != "elemwise_mul" || n3.inputs[0] != n.inputs[0])
            {
                MXNetNode new_node;
                new_node.nodes = &nodes;
                new_node.params = &params;
                new_node.op = "HardSigmoid";
                new_node.name = n2.name;
                new_node.output_size = n2.output_size;
                char alpha[16], beta[16];
                sprintf(alpha, "%f", 1.f / 6.f);
                sprintf(beta, "%f", 3.f / 6.f);
                new_node.attrs["alpha"] = alpha;
                new_node.attrs["beta"] = beta;
                new_node.inputs = n.inputs;
                new_node.subinputs = n.subinputs;

                nodes[i + 2] = new_node;

                reduced_node_count += 2;
                i += 2;
            }
            else // HardSwish <= HardSigmoid - Mul
            {
                nodes[i + 2].op = "noop_reducedncnn";
                node_reference[i - 1]--;
                node_reference.erase(node_reference.find(i + 2));
                blob_names.erase(n2.name);

                MXNetNode new_node;
                new_node.nodes = &nodes;
                new_node.params = &params;
                new_node.op = "HardSwish";
                new_node.name = n3.name;
                new_node.output_size = n3.output_size;
                char alpha[16], beta[16];
                sprintf(alpha, "%f", 1.f / 6.f);
                sprintf(beta, "%f", 3.f / 6.f);
                new_node.attrs["alpha"] = alpha;
                new_node.attrs["beta"] = beta;
                new_node.inputs = n.inputs;
                new_node.subinputs = n.subinputs;

                nodes[i + 3] = new_node;

                reduced_node_count += 3;
                i += 3;
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const FuzzerTemporaryFile file(data, size);
    const char* jsonpath = file.filename();

    std::vector<MXNetNode> nodes;
    read_mxnet_json(jsonpath, nodes);
    nodes.clear();

    return 0;
}
