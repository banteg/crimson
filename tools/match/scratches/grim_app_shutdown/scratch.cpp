class MyApp {
public:
    void cleanup(void);
    void shutdown(void);
};

void MyApp::shutdown(void)
{
    cleanup();
}
