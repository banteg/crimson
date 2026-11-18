#include <windows.h>
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>

#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern "C" {
extern IGrim2D_cpp *freeware_console_grim;
extern char console_input_buf[1024];
extern int console_input_cursor;
extern unsigned char console_input_ready;
int crt_toupper(int key);
}

extern "C" int console_input_poll(void)
{
    int key = 0;
    const int enter = 0x13;

    if (freeware_console_grim->grim_was_key_pressed(DIK_1)) {
        key = '1';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_2)) {
        key = '2';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_3)) {
        key = '3';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_4)) {
        key = '4';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_5)) {
        key = '5';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_6)) {
        key = '6';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_7)) {
        key = '7';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_8)) {
        key = '8';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_9)) {
        key = '9';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_0)) {
        key = '0';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_A)) {
        key = 'a';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_B)) {
        key = 'b';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_C)) {
        key = 'c';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_D)) {
        key = 'd';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_E)) {
        key = 'e';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_F)) {
        key = 'f';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_G)) {
        key = 'g';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_H)) {
        key = 'h';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_I)) {
        key = 'i';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_J)) {
        key = 'j';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_K)) {
        key = 'k';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_L)) {
        key = 'l';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_M)) {
        key = 'm';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_N)) {
        key = 'n';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_O)) {
        key = 'o';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_P)) {
        key = 'p';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_Q)) {
        key = 'q';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_R)) {
        key = 'r';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_S)) {
        key = 's';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_T)) {
        key = 't';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_U)) {
        key = 'u';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_V)) {
        key = 'v';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_W)) {
        key = 'w';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_X)) {
        key = 'x';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_Y)) {
        key = 'y';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_Z)) {
        key = 'z';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_SPACE)) {
        key = ' ';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_SLASH)) {
        key = '\'';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_SUBTRACT)) {
        key = '-';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_ADD)) {
        key = '+';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_COMMA)) {
        key = ',';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_PERIOD)) {
        key = '.';
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_RETURN)) {
        key = enter;
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_NUMPADENTER)) {
        key = enter;
    } else if (freeware_console_grim->grim_was_key_pressed(DIK_BACK)) {
        key = 8;
    }

    if (key && (freeware_console_grim->grim_is_key_down(DIK_RSHIFT) ||
                freeware_console_grim->grim_is_key_down(DIK_LSHIFT))) {
        if (key == '1') {
            key = '!';
        } else if (key == '2') {
            key = '"';
        } else if (key == '3') {
            key = '#';
        } else if (key == '4') {
            key = '\xa4';  // Currency sign on the Finnish keyboard layout.
        } else if (key == '5') {
            key = '%';
        } else if (key == '6') {
            key = '&';
        } else if (key == '7') {
            key = '/';
        } else if (key == '8') {
            key = '(';
        } else if (key == '9') {
            key = ')';
        } else if (key == '0') {
            key = '=';
        } else if (key == '.') {
            key = ':';
        } else if (key == ',') {
            key = ';';
        } else if (key == '-') {
            key = '_';
        } else {
            key = crt_toupper(key);
        }
    }

    if (key && !console_input_ready) {
        if (key == enter) {
            console_input_ready = 1;
            console_input_buf[console_input_cursor++] = 0;
        } else if (key == 8) {
            if (console_input_cursor > 0) {
                --console_input_cursor;
            }
            console_input_buf[console_input_cursor] = 0;
        } else {
            console_input_buf[console_input_cursor++] = (char)key;
            if (console_input_cursor >= 1024) {
                --console_input_cursor;
            }
            console_input_buf[console_input_cursor] = 0;
        }
    }
    return key;
}
