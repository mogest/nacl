require 'rake/extensiontask'
require 'rake/testtask'

Rake::TestTask.new do |t|
  t.libs << "test"
  t.test_files = FileList['test/test*.rb']
  t.verbose = true
end

spec = Gem::Specification.new do |s|
  s.name = "nacl"
  s.version = "0.2"
  s.summary = "Ruby wrapper around djb's NaCl networking and cryptography library"
  s.author = "Roger Nesbitt"
  s.email = "roger@seriousorange.com"
  s.homepage = "http://github.com/mogest/nacl"
  s.platform = Gem::Platform::RUBY
  s.files = Dir.glob('lib/**/*.rb') +
            Dir.glob('ext/**/*.{c,h,rb}')
  s.extensions = ['ext/nacl/extconf.rb']
end

Gem::PackageTask.new(spec) do |pkg|
end

Rake::ExtensionTask.new('nacl', spec) do |ext|
  ext.lib_dir = File.join('lib', 'nacl')
end

Rake::Task[:test].prerequisites << :compile
