extern "C" int demo_time_limit_ms;
extern "C" unsigned char demo_purchase_screen_active;

extern "C" void demo_purchase_interstitial_begin(void)
{
    demo_time_limit_ms = 10000;
    demo_purchase_screen_active = 1;
}
