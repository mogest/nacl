Gem::Specification.new do |s|
  s.name = "nacl"
  s.version = "0.1"
  s.summary = "Ruby wrapper around djb's NaCl networking and cryptography library"
  s.author = "Roger Nesbitt"
  s.email = "roger@seriousorange.com"
  s.homepage = "http://github.com/mogest/nacl"
  s.files = Dir.glob('lib/**/*.rb') +
            Dir.glob('ext/**/*.{c,h,rb}')
  s.extensions = ['ext/nacl/extconf.rb']
end
