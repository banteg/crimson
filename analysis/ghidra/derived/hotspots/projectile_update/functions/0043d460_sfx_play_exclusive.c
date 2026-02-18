/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: sfx_play_exclusive */
/* function_mapped: sfx_play_exclusive */
/* address: 0x0043d460 */
/* byte_range: [1303559, 1304949) */
/* sfx_play_exclusive @ 0043d460 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* mutes other sfx ids and ensures the chosen id is audible */

void sfx_play_exclusive(int sfx_id)

{
  float fVar1;
  int iVar2;
  int iVar3;
  
  if (((sfx_unmuted_flag != '\0') && (config_music_disabled == '\0')) && (config_blob == '\0')) {
    if (plugin_runtime_active_latch == '\0') {
      if (sfx_id == music_track_extra_0) {
        if (music_playlist_randomized_latch != '\0') {
          return;
        }
        if (music_playlist_entry_count == 0) {
          return;
        }
        iVar2 = crt_rand();
        music_playlist_randomized_latch = '\x01';
        sfx_id = music_playlist[iVar2 % music_playlist_entry_count];
      }
      else {
        music_playlist_randomized_latch = '\0';
      }
    }
    iVar2 = 0;
    do {
      if ((iVar2 != sfx_id) && (iVar3 = sfx_is_unmuted(iVar2), (char)iVar3 != '\0')) {
        sfx_mute_all(iVar2);
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x80);
    if (sfx_volume_table[sfx_id] <= 0.0) {
      sfx_entry_start_playback((int)(&music_entry_table + sfx_id));
      sfx_entry_set_volume((int)(&music_entry_table + sfx_id),_config_music_volume);
      fVar1 = _config_music_volume;
      sfx_mute_flags[sfx_id] = '\0';
      sfx_volume_table[sfx_id] = fVar1;
    }
  }
  return;
}



/*
