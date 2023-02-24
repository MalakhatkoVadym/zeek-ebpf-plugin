# @TEST-EXEC: zeek -NN zeek::SF |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
