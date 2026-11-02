# frozen_string_literal: true

module ISIS
  # Test helpers that are not part of the library.
  module Test
    # Install a pass-through control on +object+: every method its class
    # and the modules it includes define, public, protected or private, is
    # replaced on this one object by a method that calls the original with
    # the same arguments and block and returns what it returned. That is
    # the shape every real control has, a method replaced on the object
    # that runs the mechanism, with nothing changed. Each call is counted in
    # +calls+, by class and method, so a test can show the controls ran.
    # Returns the module.
    def self.pass_through(object, calls = Hash.new(0))
      owners = object.class.ancestors.take_while { |m| m != Object }
      names = owners.flat_map do |m|
        m.public_instance_methods(false) + m.protected_instance_methods(false) + m.private_instance_methods(false)
      end.uniq - %i[initialize]
      klass = object.class
      control = Module.new do
        names.each do |name|
          define_method(name) do |*args, &block|
            calls[[klass, name]] += 1
            super(*args, &block)
          end
          ruby2_keywords(name)
          if klass.private_method_defined?(name) then private(name)
          elsif klass.protected_method_defined?(name) then protected(name)
          end
        end
      end
      object.singleton_class.prepend(control)
      control
    end
  end
end
