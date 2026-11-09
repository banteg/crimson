#include <windows.h>
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>

#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" int crt_toupper(int);

extern "C" char freeware_read_name_key()
{
    const char no_key = '\xa7';
    char key = no_key;

    if (grim_interface_ptr->grim_was_key_pressed(DIK_1)) {
        key = '1';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_2)) {
        key = '2';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_3)) {
        key = '3';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_4)) {
        key = '4';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_5)) {
        key = '5';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_6)) {
        key = '6';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_7)) {
        key = '7';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_8)) {
        key = '8';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_9)) {
        key = '9';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_0)) {
        key = '0';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_A)) {
        key = 'a';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_B)) {
        key = 'b';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_C)) {
        key = 'c';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_D)) {
        key = 'd';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_E)) {
        key = 'e';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_F)) {
        key = 'f';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_G)) {
        key = 'g';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_H)) {
        key = 'h';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_I)) {
        key = 'i';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_J)) {
        key = 'j';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_K)) {
        key = 'k';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_L)) {
        key = 'l';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_M)) {
        key = 'm';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_N)) {
        key = 'n';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_O)) {
        key = 'o';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_P)) {
        key = 'p';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_Q)) {
        key = 'q';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_R)) {
        key = 'r';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_S)) {
        key = 's';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_T)) {
        key = 't';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_U)) {
        key = 'u';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_V)) {
        key = 'v';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_W)) {
        key = 'w';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_X)) {
        key = 'x';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_Y)) {
        key = 'y';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_Z)) {
        key = 'z';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_SPACE)) {
        key = ' ';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_SLASH)) {
        key = '\'';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_SUBTRACT)) {
        key = '-';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_ADD)) {
        key = '+';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_COMMA)) {
        key = ',';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_PERIOD)) {
        key = '.';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_RETURN)) {
        key = '\t';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_NUMPADENTER)) {
        key = '\t';
    } else if (grim_interface_ptr->grim_was_key_pressed(DIK_BACK)) {
        key = 8;
    }

    if (key != no_key && (grim_interface_ptr->grim_is_key_down(DIK_RSHIFT) ||
                grim_interface_ptr->grim_is_key_down(DIK_LSHIFT))) {
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
        } else {
            key = (char)crt_toupper(key);
        }
    }
    return key;
}
