#!/usr/bin/python3
import sys
import yaml

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
    return False

def get_rust_default_definition(rust_type, parameter):
    if not 'default' in parameter:
        return ''
    default_value = parameter['default']
    if is_value_rust_default(rust_type, default_value):
        return '        #[serde(default, skip_serializing_if = "crate::is_default")]\n'
    type_upper = rust_type.upper()
    return f'''        #[serde(default = "crate::{type_upper}::<{default_value}>::value", skip_serializing_if = "crate::{type_upper}::<{default_value}>::is_equal")]\n'''

def get_rust_struct_from_definition(name, keys):
    str = f'''    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct {name}Configuration {{
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,\n'''
    if 'parameters' in keys:
        for parameter in keys['parameters']:
            parameter_name = parameter['name'].replace('-', '_')
            rust_type = parameter['type']
            default_str = get_rust_default_definition(rust_type, parameter)
            str += default_str
            str += f'        {parameter_name}: {rust_type},\n'
    str += '    }\n'
    return str

def get_definitions_from_file(def_file):
    with open(def_file, 'rt', encoding="utf-8") as fd:
        definitions = yaml.safe_load(fd.read())
        return definitions

def gather_sections(definitions):
    sections = {}
    for key in definitions:
        entry = definitions[key]
        if 'section' in entry:
            sections[entry['section']] = True
    return sections

def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <path/to/definitions/file>')
        sys.exit(1)

    definitions = get_definitions_from_file(sys.argv[1])
    sections = gather_sections(definitions)
    for section in sections:
        print(f'''    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct {section}Configuration {{\n''')

        for definition_name, keys in definitions.items():
            if keys['section'] == section:
                print(get_rust_struct_from_definition(definition_name, keys))

        print('        }')

    print('''    #[derive(Default)]
    struct GlobalConfiguration {''')
    for section in sections:
        print(f'        {section}: {section.capitalize()}Configuration,')

    print('    }')

if __name__ == '__main__':
    main()
