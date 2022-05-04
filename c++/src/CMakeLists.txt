add_executable(ppsc
		  main.cpp
		  password.cpp
		  progress.cpp
		  request.cpp
)
target_link_libraries(ppsc Boost::system Boost::coroutine OpenSSL::Crypto
		  Boost::program_options
		  OpenSSL::SSL fmt)
install(TARGETS ppsc)
