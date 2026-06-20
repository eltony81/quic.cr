require "openssl"
 
lib LibSSL
  fun SSL_set_quic_method(ssl : Void*, meth : Void*) : Int32
end
 
puts "Linking check..."
ptr1 = ->LibSSL.SSL_set_quic_method(Void*, Void*)
puts "Linked successfully: #{ptr1}"
