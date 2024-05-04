#include "TFTPClient.h"
#include <unistd.h>

int main()
{
	TFTP::TFTPClient client("localhost");
	std::shared_ptr<uint8_t> ptr{};
	ptr.reset(new uint8_t[4096]);
	auto a = client.Get<std::vector<uint8_t>>("/srv/tftp/test.txt");
	auto b = client.Get("/srv/tftp/test.txt", ptr, 13);
	//printf("[%s] Returned err message with size %ld: %s\n", __func__, (long int) a.second, ptr.get());
	//printf("[%s] Returned err message with size %ld: %s\n", __func__, (long int) a.second.size(), a.second.data());
	//client.GetToPath("/srv/tftp/test.txt","/home/ianwillianb/Desktop/test.txt");
	//getchar();
	//std::vector<uint8_t> test{};
	//std::string test_str{};
	std::string str = "hello\n";
	std::vector<uint8_t> data{};
	std::copy(str.begin(), str.end(), std::back_inserter(data));

	const auto res = client.Put<std::string>("/srv/tftp/batata.txt","helllllo\n");

	client.Put("/srv/tftp/abcaaa.txt", ptr, 500);
	client.PutFromLocalPath("/srv/tftp/abcaaa.txt", "/home/ianwillianb/Development/TFTP/Testing/put-test.txt");
    client.Put<std::vector<uint8_t>>("/srv/tftp/batata.txt",data);
	return 0;
}
