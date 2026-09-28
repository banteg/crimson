class MyApp {
public:
    bool tick(void);
    void on_tick(void);
    void pump(void);
};

extern MyApp grim_app;

void MyApp::pump(void)
{
    if (tick()) {
        grim_app.on_tick();
    }
}
