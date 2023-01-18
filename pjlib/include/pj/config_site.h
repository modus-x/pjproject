
#define PJMEDIA_HAS_VIDEO 1
#define PJMEDIA_HAS_LIBYUV 1
#define PJMEDIA_VIDEO_DEV_HAS_SDL 0

#define PJMEDIA_HAS_L16_CODEC 0

#define PJMEDIA_HAS_ILBC_CODEC 0

#define PJMEDIA_RTP_PT_TELEPHONE_EVENTS 101
#define PJMEDIA_HAS_DTMF_FLASH 0
#define PJMEDIA_TELEPHONE_EVENT_ALL_CLOCKRATES 0

#define PJMEDIA_ADD_BANDWIDTH_TIAS_IN_SDP 0

#define PJSIP_MAX_TSX_COUNT 62
#define PJSIP_MAX_DIALOG_COUNT 62
#define PJSUA_MAX_CALLS 15
#define PJSUA_MAX_PLAYERS 15
#define PJSUA_MAX_PLAYERS 15
#define PJSUA_MAX_CONF_PORTS (PJSUA_MAX_CALLS + 2 * PJSUA_MAX_PLAYERS)
#define PJSUA_MAX_BUDDIES 24
#define PJ_DEBUG_MUTEX 0

#define PJMEDIA_VIDEO_DEV_HAS_FLUTTER 1

// windows target
#if defined(PJ_WIN32)

#define PJMEDIA_HAS_OPENH264_CODEC 1
#define PJMEDIA_WMME_DEV_USE_MMDEVICE_API 1
#define PJMEDIA_AUDIO_DEV_HAS_WMME 1
#define PJMEDIA_VIDEO_DEV_HAS_DESKTOP_SRC 1
#define PJMEDIA_VIDEO_DEV_HAS_DSHOW     1

#endif /* PJ_WIN32 */

/// linux target
#if defined(PJ_LINUX)

#endif /* PJ_LINUX */