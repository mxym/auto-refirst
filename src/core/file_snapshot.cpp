#include "prts/file_snapshot.hpp"
#include "prts/sha256.hpp"
namespace prts {
FileSnapshot snapshot_file(const std::filesystem::path& p){FileSnapshot s;s.path=p;std::error_code ec;s.exists=std::filesystem::is_regular_file(p,ec)&&!ec;if(!s.exists)return s;s.size=std::filesystem::file_size(p,ec);if(ec)s.size=0;auto t=std::filesystem::last_write_time(p,ec);if(!ec)s.write_time=t;s.sha256=sha256_file(p);return s;}
}
