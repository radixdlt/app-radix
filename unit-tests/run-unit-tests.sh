rm -rf build && cmake -Bbuild -H. && make -C build && CTEST_OUTPUT_ON_FAILURE=1 make -C build test ARGS="-V"
