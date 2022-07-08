#define LOG_FATAL (1)
#define LOG_ERR   (2)
#define LOG_WARN  (3)
#define LOG_INFO  (4)
#define LOG_DBG   (5)

#define LOG(level, ...) do {  \
                            if (level == LOG_FATAL) { \
                                fprintf(stderr, "\033[41;37mFATAL:\033[0m "); \
                                fprintf(stderr, __VA_ARGS__); \
                            } \
                            else if (level >= debug_level) { \
                                if (level == LOG_ERR) { \
                                    fprintf(stderr, "\033[31mERROR:\033[0m "); \
                                    fprintf(stderr, __VA_ARGS__); \
                                } \
                                else if (level == LOG_WARN) { \
                                    fprintf(stderr, "\033[33mWARNING:\033[0m "); \
                                    fprintf(stderr, __VA_ARGS__); \
                                } \
                                else if (level == LOG_INFO) { \
                                    fprintf(stdout, "INFO: "); \
                                    fprintf(stdout, __VA_ARGS__); \
                                } \
                                else \
                                    fprintf(stdout, __VA_ARGS__); \
                                fflush(stdout); \
                                fflush(stderr); \
                            } \
                        } while (0)
