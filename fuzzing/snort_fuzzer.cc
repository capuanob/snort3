#include <cstdio>

#include <fuzzer/FuzzedDataProvider.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main.h"
#include "main/snort.h"
#include "main/thread.h"

#define FUZZ_ARGC 8

using namespace snort;

class TemporaryFile {
public:
    TemporaryFile() : m_path{0}
    {
        std::string b;
        m_path.resize(L_tmpnam);
        std::tmpnam(m_path.data());
        m_file = std::fopen(m_path.data(), "wb+");
    }

    ~TemporaryFile()
    {
        if (nullptr != m_file)
        {
            std::fclose(m_file);
        }
    }

    [[nodiscard]] std::string get_path() const noexcept
    {
        return std::string{m_path.data(), L_tmpnam};
    }

    [[nodiscard]] FILE* get_file() const noexcept
    {
        return m_file;
    }

private:
    std::vector<char> m_path;
    FILE* m_file;
};

class ArgumentManager {
public:
    ArgumentManager()
    {
        m_argv = new char*[FUZZ_ARGC + 1];
    }
    ~ArgumentManager()
    {
        for (std::size_t i = 0; i < FUZZ_ARGC; ++i)
        {
            delete[] m_argv[i];
        }
        delete[] m_argv;
    }

    void populate_argv(std::array<std::string, FUZZ_ARGC> arg_source, const std::string& file_path) noexcept
    {
        for (std::size_t i = 0; i < FUZZ_ARGC - 1; ++i)
        {
            m_argv[i] = new char[arg_source[i].length() + 1](); // Extra space for null-terminator
            strncpy(m_argv[i], arg_source[i].data(), arg_source[i].length());
        }
        // Add the temp-file path
        m_argv[FUZZ_ARGC - 1] = new char[file_path.length() + 1]();
        strncpy(m_argv[FUZZ_ARGC - 1], file_path.data(), file_path.length());

        m_argv[FUZZ_ARGC] = nullptr;
    }

    [[nodiscard]] char** data() noexcept
    {
        return m_argv;
    }

private:
    char** m_argv;
};

// Globals used in the fuzzing process
TemporaryFile tmp_file{};
ArgumentManager arg_man{};
const std::array<std::string, FUZZ_ARGC> fuzz_argv = {
        "snort_fuzzer", "-L", "dump", "-d", "-e", "-q", "-r", "<pcap_path_here>"
};


/**
 * Performs one-time initialization of the snort library and the arrays used for argc
 * @return true on completion
 */
bool do_initialize()
{

    // Convert the argument array into a C-style heap allocated argument buffer
    arg_man.populate_argv(fuzz_argv, tmp_file.get_path());
    Snort::setup(FUZZ_ARGC, arg_man.data());

    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size)
{
    static bool is_init = do_initialize();

    // TODO: Closer, but emulating the CLI is not going to work
        // Look into finding the functionality that actually performs the dumping / PCAP processing
        // Analyzer has a static process_packet, how can we create an Analyzer

    set_thread_type(STHREAD_TYPE_MAIN);
    Snort::setup(FUZZ_ARGC, arg_man.data());

    FILE *f = tmp_file.get_file();

    // Populate the file with our current fuzz data
    std::fseek(f, 0, SEEK_SET);
    std::fwrite(data, sizeof(uint8_t), size, f);


    if ( set_mode() ) {
        snort_main();
    }

    Snort::cleanup();

    return 0;
}