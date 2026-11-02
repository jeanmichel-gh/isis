# frozen_string_literal: true

require "yaml"

module ISIS
  # A YAML configuration file, read as isisd and the simulator read theirs.
  #
  # An area address such as 49.0001 reads as a number in YAML, and 49.0010
  # as 49.001, so every list under an "areas" key, at any depth, is taken
  # as the file wrote it, from the document's own text, quoted or not.
  module ConfigFile
    module_function

    # The file's mapping, keys as written (strings), or raises
    # ArgumentError naming the file.
    def load(path)
      parse(File.read(path), source: path)
    end

    def parse(text, source: "configuration")
      data = YAML.safe_load(text, permitted_classes: [], aliases: false)
      raise ArgumentError, "#{source}: the configuration is a mapping" unless data.is_a?(Hash)

      written_areas(YAML.parse(text).root, data)
      data
    rescue Psych::SyntaxError => e
      raise ArgumentError, "#{source}: #{e.message}"
    end

    # Walks the document and the loaded data side by side, and puts each
    # "areas" list back as its scalars' own text. Aliases are refused at
    # load, so the two have the same shape.
    def written_areas(node, value)
      case node
      when Psych::Nodes::Mapping
        node.children.each_slice(2) do |k, v|
          next unless k.respond_to?(:value) && value.is_a?(Hash) && value.key?(k.value)

          if k.value == "areas"
            items = v.is_a?(Psych::Nodes::Sequence) ? v.children : [v]
            value[k.value] = items.map do |n|
              n.is_a?(Psych::Nodes::Scalar) ? n.value : raise(ArgumentError, "an area is written as 49.0001")
            end
          else
            written_areas(v, value[k.value])
          end
        end
      when Psych::Nodes::Sequence
        node.children.each_with_index { |n, i| written_areas(n, value[i]) if value.is_a?(Array) }
      end
      value
    end
  end
end
