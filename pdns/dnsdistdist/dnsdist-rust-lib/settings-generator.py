#!/usr/bin/python3

import os
import sys
import tempfile
import yaml

def quote(arg):
    """Return a quoted string"""
    return '"' + arg + '"'

def get_vector_sub_type(rust_type):
    return rust_type[4:-1]

def is_vector_of(rust_type):
    return rust_type.startswith('Vec<')

def is_type_native(rust_type):
    if is_vector_of(rust_type):
        sub_type = get_vector_sub_type(rust_type)
        return is_type_native(sub_type)
    return rust_type in ['bool', 'u8', 'u32', 'u64', 'f64', 'String']

def is_value_rust_default(rust_type, value):
    """Is a value the same as its corresponding Rust default?"""
    if rust_type == 'bool':
        return value == 'false'
    if rust_type  in ('u8', 'u32', 'u64'):
        return value in (0, '0', '')
    if rust_type == 'f64':
        return value in ('0.0', 0.0)
    if rust_type == 'String':
        return value == ''
    if rust_type == 'Vec<String>':
        # FIXME
        return True
    return False

def get_rust_field_name(name):
    return name.replace('-', '_').lower()

def get_rust_object_name(name):
    object_name = ''
    capitalize = True
    for char in name:
        if char == '-':
            capitalize = True
            continue
        if capitalize:
            char = char.upper()
            capitalize = False
        object_name += char

    return object_name

def gen_rust_vec_default_functions(name, typeName, defvalue):
    """Generate Rust code for the default handling of a vector for typeName"""
    ret = f'// DEFAULT HANDLING for {name}\n'
    ret += f'fn default_value_{name}() -> Vec<dnsdistsettings::{typeName}> {{\n'
    ret += f'    let msg = "default value defined for `{name}\' should be valid YAML";'
    ret += f'    let deserialized: Vec<dnsdistsettings::{typeName}> = serde_yaml::from_str({quote(defvalue)}).expect(&msg);\n'
    ret += f'    deserialized\n'
    ret += '}\n'
    ret += f'fn default_value_equal_{name}(value: &Vec<dnsdistsettings::{typeName}>)'
    ret += '-> bool {\n'
    ret += f'    let def = default_value_{name}();\n'
    ret += '    &def == value\n'
    ret += '}\n\n'
    return ret

# Example snippet generated
# fn default_value_general_query_local_address() -> Vec<String> {
#    vec![String::from("0.0.0.0"), ]
#}
#fn default_value_equal_general_query_local_address(value: &Vec<String>) -> bool {
#    let def = default_value_general_query_local_address();
#    &def == value
#}
def gen_rust_stringvec_default_functions(default, name):
    """Generate Rust code for the default handling of a vector for Strings"""
    ret = f'// DEFAULT HANDLING for {name}\n'
    ret += f'fn default_value_{name}() -> Vec<String> {{\n'
    parts = re.split('[ \t,]+', default)
    if len(parts) > 0:
        ret += '    vec![\n'
        for part in parts:
            if part == '':
                continue
            ret += f'        String::from({quote(part)}),\n'
        ret += '    ]\n'
    else:
        ret  += '    vec![]\n'
    ret += '}\n'
    ret += f'fn default_value_equal_{name}(value: &Vec<String>) -> bool {{\n'
    ret += f'    let def = default_value_{name}();\n'
    ret += '    &def == value\n'
    ret += '}\n\n'
    return ret

def gen_rust_default_functions(rust_type, default, name):
    """Generate Rust code for the default handling"""
    if rust_type in ['Vec<String>']:
        return gen_rust_stringvec_default_functions(default, name)
    ret = f'// DEFAULT HANDLING for {name}\n'
    ret += f'fn default_value_{name}() -> {rust_type} {{\n'
    rustdef = quote(default)
    ret += f"    String::from({rustdef})\n"
    ret += '}\n'
    if rust_type == 'String':
        rust_type = 'str'
    ret += f'fn default_value_equal_{name}(value: &{rust_type})'
    ret += '-> bool {\n'
    ret += f'    value == default_value_{name}()\n'
    ret += '}\n\n'
    return ret

def get_rust_serde_annotations(rust_type, default, rename, obj, field, default_functions):
    rename_value = f'rename = "{rename}", ' if rename else ''
    if default is None:
        if not rename_value:
            return ''
        return f'#[serde({rename_value})]'
    if default is True or is_value_rust_default(rust_type, default):
        return f'#[serde({rename_value}default, skip_serializing_if = "crate::is_default")]'
    type_upper = rust_type.capitalize()
    if rust_type == 'bool':
        return f'''#[serde({rename_value}default = "crate::{type_upper}::<{default}>::value", skip_serializing_if = "crate::if_true")]'''
    if rust_type == 'String' or rust_type == 'Vec<String>':
        basename = obj + '_' + field
        default_functions.append(gen_rust_default_functions(rust_type, default, basename))
        return f'''#[serde({rename_value}default = "crate::default_value_{basename}", skip_serializing_if = "crate::default_value_equal_{basename}")]'''
    return f'''#[serde({rename_value}default = "crate::{type_upper}::<{default}>::value", skip_serializing_if = "crate::{type_upper}::<{default}>::is_equal")]'''

def get_rust_struct_fields_from_definition(name, keys, default_functions, indent_spaces):
    if not 'parameters' in keys:
        return ''
    output = ''
    indent = ' '*indent_spaces
    for parameter in keys['parameters']:
        parameter_name = get_rust_field_name(parameter['name']) if not 'rename' in parameter else parameter['rename']
        rust_type = parameter['type']
        if 'rust-type' in parameter:
            rust_type = parameter['rust-type']
        # cxx does not support Enums, so we have to convert them to opaque types
        if rust_type == 'Action':
            rust_type = 'SharedDNSAction'
        elif rust_type == 'ResponseAction':
            rust_type = 'SharedDNSResponseAction'
        elif rust_type == 'Selector':
            rust_type = 'SharedDNSSelector'
        elif rust_type == 'Vec<Selector>':
            rust_type = 'Vec<SharedDNSSelector>'
        rename = parameter['name'] if parameter_name != parameter['name'] else None
        default_str = get_rust_serde_annotations(rust_type, parameter['default'] if 'default' in parameter else None, rename, get_rust_field_name(name), parameter_name, default_functions)
        if default_str:
            output += indent + default_str + '\n'
        output += f'{indent}{parameter_name}: {rust_type},\n'

    return output

def get_rust_struct_from_definition(name, keys, default_functions, indent_spaces=4):
    if not 'parameters' in keys:
        return ''
    obj_name = get_rust_object_name(name)
    indent = ' '*indent_spaces
    name_field = ''
    output = ''
    if not 'skip-serde' in keys or not keys['skip-serde']:
        output += f'''{indent}#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
{indent}#[serde(deny_unknown_fields)]
'''
    output += f'''{indent}struct {obj_name}Configuration {{
{name_field}'''
    indent_spaces += 4
    indent = ' '*indent_spaces
    if 'generate-name-field' in keys and keys['generate-name-field'] is True:
        name_field = f'''{indent}#[serde(default, skip_serializing_if = "crate::is_default")]
{indent}name: String,\n'''
    output += get_rust_struct_fields_from_definition(name, keys, default_functions, indent_spaces)
    output += '    }\n'
    return output

def should_validate_type(rust_type):
    if is_vector_of(rust_type):
        sub_type = get_vector_sub_type(rust_type)
        return should_validate_type(sub_type)
    if rust_type in ['bool', 'u8', 'u16', 'u32', 'u64', 'f64', 'String']:
        return False
    if rust_type in ['Selector', 'dnsdistsettings::SelectorsConfiguration']:
        return False
    return True

def get_validation_for_field(field_name, rust_type):
    if not should_validate_type(rust_type):
        return ''
    if not is_vector_of(rust_type):
        return f'        self.{field_name}.validate()?;\n'
    else:
        return f'''        for sub_type in &self.{field_name} {{
        sub_type.validate()?;
    }}
'''

def get_struct_validation_function_from_definition(name, parameters):
    if len(parameters) == 0:
        return ''
    struct_name = get_rust_object_name(name)
    output = f'''impl dnsdistsettings::{struct_name}Configuration {{
    fn validate(&self) -> Result<(), ValidationError> {{
'''
    for parameter in parameters:
        field_name = get_rust_field_name(parameter['name']) if parameter['name'] != 'namespace' else 'name_space'
        rust_type = parameter['type']
        output += get_validation_for_field(field_name, rust_type)
    output += '''        Ok(())
    }
}'''
    return output

def get_definitions_from_file(def_file):
    with open(def_file, 'rt', encoding="utf-8") as fd:
        definitions = yaml.safe_load(fd.read())
        return definitions

def gather_sections(definitions):
    sections = {}
    for key in definitions:
        entry = definitions[key]
        if 'section' in entry:
            section_name = entry['section']
            sections[section_name] = entry['type'] if 'type' in entry else None
    return sections

def get_rust_obj_for_section(def_name, def_keys):
    if 'type' in def_keys and def_keys['type'] == 'list':
        name = get_rust_object_name(def_name)
        return (f'Vec<{name}Configuration>', f'Vec<dnsdistsettings::{name}Configuration>')
    name = get_rust_object_name(def_name)
    return (f'{name}Configuration', f'dnsdistsettings::{name}Configuration')

def include_file(out_fp, include_file_name):
    with open(include_file_name, mode='r', encoding='utf-8') as in_fp:
        out_fp.write(f'// START INCLUDE {include_file_name}\n')
        out_fp.write(in_fp.read())
        out_fp.write(f'// END INCLUDE {include_file_name}\n')

def generate_flat_settings_for_cxx(definitions, out_file_path):
    cxx_flat_settings_fp = tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', dir=out_file_path)

    include_file(cxx_flat_settings_fp, out_file_path + 'dnsdist-configuration-yaml-items-cxx-pre-in.cc')

    # first we do runtime-settable settings
    cxx_flat_settings_fp.write('''#if defined(HAVE_YAML_CONFIGURATION)
#include "rust/cxx.h"
#include "rust/lib.rs.h"

namespace dnsdist::configuration::yaml
{
void convertRuntimeFlatSettingsFromRust(const dnsdist::rust::settings::GlobalConfiguration& yamlConfig)
{
  dnsdist::configuration::updateRuntimeConfiguration([&yamlConfig](dnsdist::configuration::RuntimeConfiguration& config) {\n''');
    for category_name, keys in definitions.items():
        if not 'parameters' in keys or not 'section' in keys:
            continue

        category_name = get_rust_field_name(category_name) if keys['section'] == 'global' else get_rust_field_name(keys['section']) + '.' + get_rust_field_name(category_name)
        for parameter in keys['parameters']:
            if not 'internal-field-name' in parameter or not 'runtime-configurable' in parameter or not parameter['runtime-configurable']:
                continue
            internal_field_name = parameter['internal-field-name']
            rust_field_name = get_rust_field_name(parameter['name']) if not 'rename' in parameter else parameter['rename']
            default = parameter['default'] if parameter['type'] != 'String' else '"' + parameter['default'] + '"'
            cxx_flat_settings_fp.write(f'    if (yamlConfig.{category_name}.{rust_field_name} != {default} && config.{internal_field_name} == {default}) {{\n')
            if parameter['type'] != 'String':
                cxx_flat_settings_fp.write(f'        config.{internal_field_name} = yamlConfig.{category_name}.{rust_field_name};\n')
            else:
                cxx_flat_settings_fp.write(f'        config.{internal_field_name} = std::string(yamlConfig.{category_name}.{rust_field_name});\n')
            cxx_flat_settings_fp.write(f'    }}\n')

    cxx_flat_settings_fp.write('  });\n');
    cxx_flat_settings_fp.write('''}\n''');

    # then immutable ones
    cxx_flat_settings_fp.write('''void convertImmutableFlatSettingsFromRust(const dnsdist::rust::settings::GlobalConfiguration& yamlConfig)
{
  dnsdist::configuration::updateImmutableConfiguration([&yamlConfig](dnsdist::configuration::ImmutableConfiguration& config) {\n''');
    for category_name, keys in definitions.items():
        if not 'parameters' in keys or not 'section' in keys:
            continue

        category_name = get_rust_field_name(category_name) if keys['section'] == 'global' else get_rust_field_name(keys['section']) + '.' + get_rust_field_name(category_name)
        for parameter in keys['parameters']:
            if not 'internal-field-name' in parameter or not 'runtime-configurable' in parameter or parameter['runtime-configurable']:
                continue
            internal_field_name = parameter['internal-field-name']
            rust_field_name = get_rust_field_name(parameter['name']) if not 'rename' in parameter else parameter['rename']
            default = parameter['default'] if parameter['type'] != 'String' else '"' + parameter['default'] + '"'
            cxx_flat_settings_fp.write(f'    if (yamlConfig.{category_name}.{rust_field_name} != {default} && config.{internal_field_name} == {default}) {{\n')
            if parameter['type'] != 'String':
                cxx_flat_settings_fp.write(f'        config.{internal_field_name} = yamlConfig.{category_name}.{rust_field_name};\n')
            else:
                cxx_flat_settings_fp.write(f'        config.{internal_field_name} = std::string(yamlConfig.{category_name}.{rust_field_name});\n')
            cxx_flat_settings_fp.write(f'    }}\n')

    cxx_flat_settings_fp.write('  });\n');
    cxx_flat_settings_fp.write('''}\n
}
#endif /* defined(HAVE_YAML_CONFIGURATION) */
''')

    os.rename(cxx_flat_settings_fp.name, out_file_path + 'dnsdist-configuration-yaml-items-cxx.cc')

def generate_actions_config(output, response, default_functions):
    suffix = 'ResponseAction' if response else 'Action'
    actions_definitions = get_actions_definitions(response)
    action_buffer = ''
    for action in actions_definitions:
        name = get_rust_object_name(action['name'])
        struct_name = f'{name}{suffix}Configuration'
        indent = ' ' * 4
        action_buffer += f'''{indent}#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
{indent}#[serde(deny_unknown_fields)]
{indent}struct {struct_name} {{\n'''

        indent = ' ' * 8
        action_buffer += f'''{indent}#[serde(default, skip_serializing_if = "crate::is_default")]
{indent}name: String,\n'''

        action_buffer += get_rust_struct_fields_from_definition(struct_name, action, default_functions, 8)

        action_buffer += '    }\n\n'

    output.write(action_buffer)

def generate_cpp_action_headers():
    cpp_action_headers_fp = tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', dir='..')
    header_buffer = ''

    # query actions
    actions_definitions = get_actions_definitions(False)
    suffix = 'Action'
    for action in actions_definitions:
        name = get_rust_object_name(action['name'])
        struct_name = f'{name}{suffix}Configuration'
        header_buffer += f'struct {struct_name};\n'
        header_buffer += f'std::shared_ptr<DNS{suffix}Wrapper> get{name}{suffix}(const {struct_name}& config);\n'

    # response actions
    actions_definitions = get_actions_definitions(True)
    suffix = 'ResponseAction'
    for action in actions_definitions:
        name = get_rust_object_name(action['name'])
        struct_name = f'{name}{suffix}Configuration'
        header_buffer += f'struct {struct_name};\n'
        header_buffer += f'std::shared_ptr<DNS{suffix}Wrapper> get{name}{suffix}(const {struct_name}& config);\n'

    cpp_action_headers_fp.write(header_buffer)
    os.rename(cpp_action_headers_fp.name, '../dnsdist-rust-bridge-actions-generated.hh')

def get_cpp_parameters(struct_type, struct_name, parameters, skip_name):
    output = ''
    for parameter in parameters:
        name = parameter['name']
        ptype = parameter['type']
        if name == 'name' and skip_name:
            continue
        pname = get_rust_field_name(name)
        if len(output) > 0:
            output += ', '
        field = f'{struct_name}.{pname}'
        if ptype == 'PacketBuffer':
            field = f'PacketBuffer({field}.data(), {field}.data() + {field}.size())'
        elif ptype == 'DNSName':
            field = f'DNSName(std::string({field}))'
        elif ptype == 'ComboAddress':
            field = f'ComboAddress(std::string({field}))'
        elif ptype == 'String':
            field = f'std::string({field})'
        elif ptype == 'ResponseConfig':
            field = f'convertResponseConfig({field})'
        elif ptype == 'Vec<SVCRecordParameters>':
            field = f'convertSVCRecordParameters({field})'
        elif ptype == 'SOAParams':
            field = f'convertSOAParams({field})'
        elif ptype in ['dnsdist::actions::LuaActionFunction', 'dnsdist::actions::LuaActionFFIFunction', 'dnsdist::actions::LuaResponseActionFunction', 'dnsdist::actions::LuaResponseActionFFIFunction']:
            field = f'convertLuaFunction<{ptype}>("{struct_type}", {field})'
        output += field
    return output

def generate_cpp_action_wrappers():
    cpp_action_wrappers_fp = tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', dir='..')
    wrappers_buffer = ''

    # query actions
    actions_definitions = get_actions_definitions(False)
    suffix = 'Action'
    for action in actions_definitions:
        if 'skip-rust' in action and action['skip-rust']:
            continue
        name = get_rust_object_name(action['name'])
        struct_name = f'{name}{suffix}Configuration'
        parameters = get_cpp_parameters(struct_name, 'config', action['parameters'], True) if 'parameters' in action else ''
        wrappers_buffer += f'''std::shared_ptr<DNS{suffix}Wrapper> get{name}{suffix}(const {struct_name}& config)
{{
  auto action = dnsdist::actions::get{name}{suffix}({parameters});
  return newDNSActionWrapper(std::move(action), config.name);
}}
'''

    # response actions
    actions_definitions = get_actions_definitions(True)
    suffix = 'ResponseAction'
    for action in actions_definitions:
        if 'skip-rust' in action and action['skip-rust']:
            continue
        name = get_rust_object_name(action['name'])
        struct_name = f'{name}{suffix}Configuration'
        parameters = get_cpp_parameters(struct_name, 'config', action['parameters'], True) if 'parameters' in action else ''
        wrappers_buffer += f'''std::shared_ptr<DNS{suffix}Wrapper> get{name}{suffix}(const {struct_name}& config)
{{
  auto action = dnsdist::actions::get{name}{suffix}({parameters});
  return newDNSResponseActionWrapper(std::move(action), config.name);
}}
'''

    cpp_action_wrappers_fp.write(wrappers_buffer)
    os.rename(cpp_action_wrappers_fp.name, '../dnsdist-rust-bridge-actions-generated.cc')

def generate_rust_actions_enum(output, response):
    suffix = 'ResponseAction' if response else 'Action'
    actions_definitions = get_actions_definitions(response)
    enum_buffer = f'''#[derive(Default, Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "type")]
enum {suffix} {{
    #[default]
    Default,
'''

    for action in actions_definitions:
        name = get_rust_object_name(action['name'])
        struct_name = f'{name}{suffix}Configuration'
        enum_buffer += f'    {name}(dnsdistsettings::{struct_name}),\n'

    enum_buffer += '}\n\n'

    output.write(enum_buffer)

def get_actions_definitions(response):
    def_file = '../dnsdist-response-actions-definitions.yml' if response else '../dnsdist-actions-definitions.yml'
    return get_definitions_from_file(def_file)

def generate_cpp_action_functions_callable_from_rust(output):
    output_buffer = '''
    /*
     * Functions callable from Rust (actions)
     */
    unsafe extern "C++" {
'''
    # first query actions
    actions_definitions = get_actions_definitions(False)
    suffix = 'Action'
    for action in actions_definitions:
        name = get_rust_object_name(action['name'])
        output_buffer += f'        fn get{name}{suffix}(config: &{name}{suffix}Configuration) -> SharedPtr<DNS{suffix}Wrapper>;\n'

    # then response actions
    actions_definitions = get_actions_definitions(True)
    suffix = 'ResponseAction'
    for action in actions_definitions:
        name = get_rust_object_name(action['name'])
        output_buffer += f'        fn get{name}{suffix}(config: &{name}{suffix}Configuration) -> SharedPtr<DNS{suffix}Wrapper>;\n'

    output_buffer += '    }\n'
    output.write(output_buffer)

def generate_rust_action_to_config(output, response):
    suffix = 'ResponseAction' if response else 'Action'
    actions_definitions = get_actions_definitions(response)
    function_name = 'get_one_action_from_serde' if not response else 'get_one_response_action_from_serde'
    enum_buffer = f'''fn {function_name}(action: &{suffix}) -> Option<dnsdistsettings::SharedDNS{suffix}> {{
    match action {{
        {suffix}::Default => {{}}
'''

    for action in actions_definitions:
        name = get_rust_object_name(action['name'])
        var = name.lower()
        struct_name = f'{name}{suffix}Configuration'
        enum_buffer += f'''        {suffix}::{name}({var}) => {{
            let tmp_action = dnsdistsettings::get{name}{suffix}(&{var});
            return Some(dnsdistsettings::SharedDNS{suffix} {{
                action: tmp_action,
            }});
        }}
'''

    enum_buffer += '''    }
    None
}
'''

    output.write(enum_buffer)

def handle_nested_structures(generated_fp, definitions, default_functions, validation_functions):
    for definition_name, keys in definitions.items():
        if 'section' in keys and keys['section'] != 'none':
            continue

        generated_fp.write(get_rust_struct_from_definition(definition_name, keys, default_functions) + '\n')
        validation_functions.append(get_struct_validation_function_from_definition(definition_name, keys['parameters'] if 'parameters' in keys else []))

def handle_global_structures(generated_fp, sections, definitions, global_objects, default_functions, validation_functions):
    for section, section_type in sections.items():
        for definition_name, keys in definitions.items():
            if not 'section' in keys:
                continue
            if keys['section'] != section:
                continue

            if section == 'global':
                if 'type' in keys and keys['type'] != 'list':
                    rust_type = keys['type']
                    print(f'Found global, non-list type {rust_type} for {definition_name}')
                    if is_type_native(rust_type):
                        global_objects[definition_name] = (rust_type, rust_type)
                    else:
                        if is_vector_of(rust_type):
                            sub_type = get_vector_sub_type(rust_type)
                            global_objects[definition_name] = (rust_type, 'Vec<dnsdistsettings::' + sub_type + '>')
                        else:
                            global_objects[definition_name] = (rust_type, 'dnsdistsettings::' + rust_type)
                else:
                    global_objects[definition_name] = get_rust_obj_for_section(definition_name, keys)

            generated_fp.write(get_rust_struct_from_definition(definition_name, keys, default_functions) + '\n')
            validation_functions.append(get_struct_validation_function_from_definition(definition_name, keys['parameters'] if 'parameters' in keys else []))

def handle_sub_structures(generated_fp, sections, definitions, global_objects, validation_functions):
    for section, section_type in sections.items():
        if section == 'global':
            continue

        # now handling the structure for the section itself
        if section_type is not None and section_type != 'list':
            global_objects[section] = (section_type, section_type)
            continue

        global_objects[section] = (get_rust_object_name(section) + 'Configuration', 'dnsdistsettings::' + get_rust_object_name(section) + 'Configuration')

        section_name = get_rust_object_name(section)
        # generate the first-level structure that is directly under 'global'
        section_struct_parameters = []
        generated_fp.write(f'''    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct {section_name}Configuration {{\n''')
        for definition_name, keys in definitions.items():
            if not 'section' in keys or keys['section'] != section:
                continue
            field_name = get_rust_field_name(definition_name) if not 'rename' in keys else keys['rename']
            name = get_rust_object_name(definition_name)
            obj_type = f'{name}Configuration' if not 'type' in keys or keys['type'] != 'list' else f'Vec<{name}Configuration>'
            generated_fp.write('        #[serde(default, skip_serializing_if = "crate::is_default")]\n')
            generated_fp.write(f'        {field_name}: {obj_type},\n')
            section_struct_parameters.append({'name': field_name, 'type': obj_type})

        generated_fp.write('    }\n')
        validation_functions.append(get_struct_validation_function_from_definition(section_name, section_struct_parameters))

def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <path/to/definitions/file>')
        sys.exit(1)

    src_dir = './'
    definitions = get_definitions_from_file(sys.argv[1])
    default_functions = []
    validation_functions = []
    sections = gather_sections(definitions)
    global_objects = {}

    generate_cpp_action_headers()
    generate_cpp_action_wrappers()

    generated_fp = tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', dir=src_dir + '/rust/src/')
    include_file(generated_fp, src_dir + 'rust-pre-in.rs')

    generate_actions_config(generated_fp, False, default_functions)
    generate_actions_config(generated_fp, True, default_functions)

    generate_flat_settings_for_cxx(definitions, src_dir)

    # handle structures that are not directly under a first-level section
    handle_nested_structures(generated_fp, definitions, default_functions, validation_functions)

    # for each section, including the global one, generate the structures below the section one
    handle_global_structures(generated_fp, sections, definitions, global_objects, default_functions, validation_functions)
    handle_sub_structures(generated_fp, sections, definitions, global_objects, validation_functions)

    # the cxx-compatible Global configuration object
    generated_fp.write('''    #[derive(Default)]
    struct GlobalConfiguration {\n''')
    for obj, names in global_objects.items():
        field_name = get_rust_field_name(obj)
        field_type = names[0]
        if field_type == 'SelectorsConfiguration':
            field_type = 'Vec<SharedDNSSelector>'
        elif field_type == 'Selector':
            field_type = 'SharedDNSSelector'
        elif field_type == 'Action':
            field_type = 'SharedDNSAction'
        elif field_type == 'ResponseAction':
            field_type = 'SharedDNSResponseAction'
        elif field_type == 'Vec<Selector>':
            field_type = 'Vec<SharedDNSSelector>'
        generated_fp.write(f'        {field_name}: {field_type},\n')

    generated_fp.write('    }\n')

    generate_cpp_action_functions_callable_from_rust(generated_fp)

    include_file(generated_fp, src_dir + 'rust-middle-in.rs')

    generate_rust_actions_enum(generated_fp, False)
    generate_rust_actions_enum(generated_fp, True)

    # then the Serde one
    generated_fp.write('''#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct GlobalConfigurationSerde {\n''')
    for obj, names in global_objects.items():
        field_name = get_rust_field_name(obj)
        rename = obj if field_name != obj else None
        default_str = get_rust_serde_annotations(names[0], True, rename, field_name, 'global', default_functions)
        if default_str:
            generated_fp.write('    ' + default_str + '\n')
        rust_type = names[1]
        if rust_type == 'dnsdistsettings::SelectorsConfiguration':
            rust_type = 'Vec<Selector>'
        if rust_type == 'Vec<dnsdistsettings::QueryRulesConfiguration>':
            rust_type = 'Vec<QueryRulesConfigurationSerde>'
        if rust_type == 'Vec<dnsdistsettings::ResponseRulesConfiguration>':
            rust_type = 'Vec<ResponseRulesConfigurationSerde>'
        generated_fp.write(f'    {field_name}: {rust_type},\n')

    generated_fp.write('}\n')

    # Validation function for the global section
    generated_fp.write('impl GlobalConfigurationSerde {\n')
    generated_fp.write('    fn validate(&self) -> Result<(), ValidationError> {\n')
    for obj, names in global_objects.items():
        field_name = get_rust_field_name(obj)
        rust_type = names[1]
        if rust_type == 'Action':
            rust_type = 'SharedDNSAction'
        elif rust_type == 'ResponseAction':
            rust_type = 'SharedDNSResponseAction'
        elif rust_type == 'Selector':
            rust_type = 'SharedDNSSelector'
        elif rust_type == 'SelectorsConfiguration':
            rust_type = 'Vec<SharedDNSSelector>'
        generated_fp.write(get_validation_for_field(field_name, rust_type))
    generated_fp.write('        Ok(())\n')
    generated_fp.write('    }\n')
    generated_fp.write('}\n\n')

    # the generated functions for the default values and validation
    for function_def in default_functions:
        generated_fp.write(function_def + '\n')

    for function_def in validation_functions:
        generated_fp.write(function_def + '\n')

    generate_rust_action_to_config(generated_fp, False)
    generate_rust_action_to_config(generated_fp, True)

    include_file(generated_fp, src_dir + 'rust-post-in.rs')

    os.rename(generated_fp.name, src_dir + '/rust/src/lib.rs')

if __name__ == '__main__':
    main()