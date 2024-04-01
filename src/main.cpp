#include "TFTPClient.h"

int main()
{
	TFTP::TFTPClient client("localhost");
	//std::shared_ptr<uint8_t> ptr{};
	//ptr.reset(new uint8_t[4096]);
	//auto a = client.Get<std::vector<uint8_t>>("/srv/tftp/test.txt");
	//const auto a = client.Get("/srv/tftp/test.txt", ptr, 13);
	//printf("[%s] Returned err message with size %ld: %s\n", __func__, (long int) a.second, ptr.get());
	//printf("[%s] Returned err message with size %ld: %s\n", __func__, (long int) a.second.size(), a.second.data());
	client.GetToPath("/srv/tftp/test.txt","/home/ianwillianb/Desktop/test.txt");
	getchar();
	std::vector<uint8_t> test{};
	std::string test_str{};
	return 0;
}
