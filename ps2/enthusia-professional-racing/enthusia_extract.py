#!/usr/bin/env python3
"""
enthusia_extract.py: extractor for Enthusia Professional Racing (PS2, SLUS-209.67)

https://github.com/ravenDS/enthusia-extract

usage:
  python3 enthusia_extract.py <path-to-enthusia> [-o OUTPUT] [--car-names en|jp|off] [--map-names on|off] [-v]
  or
  python3 enthusia_extract.py <path-to-enthusia>

<path-to-enthusia> is the folder holding D000.BIN and D001.BIN, or the disc root with an ENTHUSIA folder
without -o, files go to <path-to-enthusia>/enthusia_extracted (created, or written over when it exists)

container
  D000.BIN: flat array of little-endian u32, one per slot, no header
  each value is the start LBA of the slot inside D001.BIN, slot i spans sectors [toc[i], toc[i+1])
  last element is a sentinel equal to len(D001.BIN)/2048, toc[i] == toc[i+1] means an unused slot
  D001.BIN: raw payload, 2048-byte sectors, no padding between slots
  TeFileManage::getArcEntry 0x272D08 reads toc[fid] directly, so file id is the slot index

group layout
  TeFileManage::resolve 0x271620 walks 31 group objects at mgr+0x108 and subtracts each group's getSize() until id falls inside one
  so each group base is the running sum of the sizes of the groups registered before it
  order comes from the 31 setGroup (0x271498) calls in 0x271A7C, sizes are constants at vtable+0x0C
  exceptions: both maker groups (runtime maker count, 62 each) and five list-driven groups whose count is set by their initialisers (0x279FB0, 0x270458, 0x271B00, 0x27E6E0, 0x27E728)
  folder names come from debug path table at 0x4C8B20, groups missing from it are named after their class

file naming
  car groups (carpk, selcarpk, cariconpk, carlogopk): car index -> number + name
  car table is a static ELF table at 0x485938, 211 records {u32 number, u32 field4, char *name_jp, char *name_en}, embedded below as CARS
  numbers are checked against all_cbd.bin (slot 108) of the archive being extracted
  0x1DAB78 numberOf(idx) gives synthetic numbers past the table: 9999789+idx below 221, 19999779+idx above
  0x1DAA28 picks the English name when 0x377D44 != 0 (console language 1-4), so a US console shows the English column
  mappk: index -> map number from u16 tables at 0x47D670 / 0x47D768 (COURSE_NUMBERS), file NNN_00
  course snapshots and minimaps (crssnapimgpk, crssnapiconpk, minimapselpk, minimapracepk): index is the map number
  map names come from string table 0x378CC0 through 0x197230 (MAP_NAMES), 6xx/8xx variants use the name of NNN-600
  small list groups (etc, irx, mc_icon, datamng, filemng, elrace): names from their list initialisers
  bgm and tutorial use the game's own formats "bgm%05d.bin" (0x4923D0) and "tutorial%03d.bin" (0x47F2A0)
  makers, selpk, bgimgpk, crsstsbig/small and se/* keep numeric names

nested archive (magic 0x1000FC87)
  u32 magic, u32 flags = 0, then struct { u32 size; u32 end; } toc[count]
  toc[0].size is the entry count (including toc[0]), toc[0].end is where the payload begins
  entry k (1 <= k < count) occupies [toc[k-1].end, toc[k-1].end + toc[k].size), toc[k].end == align16(that end)
"""

import argparse
import csv
import os
import struct
import sys
import unicodedata

SECTOR = 2048
COPY_CHUNK = 8 << 20
ALL_CBD_FID = 108          # etc/etc index 5
OUTPUT_DIR_NAME = "enthusia_extracted"

# (count, directory, class, stored in archive, naming rule)
# bases are prefix sums of the counts
GROUPS = [
    (  61, "bgm/bgm",             "WSBgmFileGrp_c",                 True,  "bgm"),
    (  30, "movie/movie",         "WSMovieFileGrp_c",               True,  None),
    (  10, "irx/irx",             "TeIrxFileGroup_t",               False, "list"),
    (   2, "mc_icon/mc_icon",     "okFileGroup_t",                  True,  "list"),
    (   9, "etc/etc",             "TeEtcFileGroup_t",               True,  "list"),
    ( 200, "pack/mappk",          "TeFgrpMapPack_t",                True,  "course_index"),
    ( 222, "pack/carpk",          "TeFgrpCarPack_t",                True,  "car_index"),
    ( 222, "pack/selcarpk",       "TeFgrpSelCarPack_t",             True,  "car_index"),
    ( 130, "pack/selpk",          "TeSelPkdtFileGroup_t",           True,  None),
    (  12, "pack/bgimgpk",        "TeBgImagePkdtFileGroup_t",       True,  None),
    ( 211, "pack/cariconpk",      "TeCarIconPkdtFileGroup_t",       True,  "car_index"),
    ( 211, "pack/carlogopk",      "TeCarLogoPkdtFileGroup_t",       True,  "car_index"),
    (  62, "pack/makerlogopk",    "TeMakerLogoPkdtFileGroup_t",     True,  None),
    (  62, "pack/makericonpk",    "TeMakerIconPkdtFileGroup_t",     True,  None),
    ( 320, "pack/crssnapimgpk",   "TeCrsSnapImagePkdtFileGroup_t",  True,  "course_number"),
    ( 320, "pack/crssnapiconpk",  "TeCrsSnapIconPkdtFileGroup_t",   True,  "course_number"),
    ( 320, "pack/minimapselpk",   "TeMiniMapSelPkdtFileGroup_t",    True,  "course_number"),
    ( 320, "pack/minimapracepk",  "TeMiniMapRacePkdtFileGroup_t",   True,  "course_number"),
    (  12, "pack/crsstsbigpk",    "TeCrsStatBigPkdtFileGroup_t",    True,  None),
    (  12, "pack/crsstssmallpk",  "TeCrsStatSmallPkdtFileGroup_t",  True,  None),
    (   1, "se/sys",              "WSSdSysSeGroup_c",               True,  None),
    ( 120, "se/amb",              "WSSdAmbSeGroup_c",               True,  None),
    ( 880, "se/car",              "WSSdCarSeGroup_c",               True,  None),
    ( 120, "se/squeal",           "WSSdSqealSeGroup_c",             True,  None),
    (   1, "se/optcar",           "WSSdOptCarSeGroup_c",            True,  None),
    ( 100, "tutorial/tutorial",   "J_FileGroup_tutorial_t",         True,  "tutorial"),
    (   1, "game/elrace",         "mynFgrpEtc_rcd_t",               True,  "list"),
    (   2, "_datamng",            "TeDataMngFileGroup_t",           False, "list"),
    (   2, "_filemng",            "TeFileMngFileGroup_t",           False, "list"),
    (  99, "replay/replay",       "Ts_FileGroup_replay_t",          False, None),
    (   5, "record/record",       "Ts_recordFileGroup_t",           False, None),
]

GROUP_FILE_NAMES = {
    "irx/irx": ["ioprp300.img", "sio2man.irx", "padman.irx", "mcman.irx",
                "mcserv.irx", "usbd.irx", "lgdevW.irx", "usbhandle.irx",
                "libsd.irx", "sddrviop.irx"],
    "mc_icon/mc_icon": ["system.ico", "replay.ico"],
    "etc/etc": ["pvram_000_a.bin", "pvram_001_a.bin", "fontB.tm2",
                "fontdic.kbi.gs", "ef_cmn.ef", "all_cbd.bin", "all_icd.bin",
                "shashu_x_course.bin", "099_00_mesh.vgs"],
    "_datamng": ["d000.bin", "d001.bin"],
    "_filemng": ["archivelist.log", "writecdvd.txt"],
    "game/elrace": ["el_race_data.rcd"],
}

# mappk index -> map number (u16 tables at 0x47D670 / 0x47D768), indices 80+ are unused
COURSE_NUMBERS = [
      0,   1,   2,   3,   4,   5,   7,   8,  10,  11,
     12,  13,  14,  15,  16,  17,  18,  20,  21,  22,
     23,  26,  28,  29,  30,  31,  32,  33,  34,  35,
     36,  37,  38,  39,  40,  41,  42,  43,  44,  45,
     46,  47,  48,  99, 112, 113, 114, 115, 116, 117,
    118, 119, 201, 202, 203, 204, 205, 207, 208, 210,
    211, 212, 213, 214, 215, 216, 217, 218, 221, 222,
    223, 247, 248, 608, 615, 620, 621, 808, 815, 821,
]

# map number -> name, from string table 0x378CC0 ('@' + letter in the game strings is an umlaut)
MAP_NAMES = {
    1: "AUTUMN HILL",
    2: "AUTUMN MOUNTAIN",
    3: "VICTORIA GARDEN",
    4: "VICTORIA ROAD",
    5: "ROUTE de la SEINE",
    7: "BURGENSCHLUCHT",
    8: "WINTERTRAUM",
    10: "MARCO STRADA",
    11: "MARCO STRADA",
    12: "TSUKUBA CIRCUIT",
    13: "TSUKUBA CIRCUIT",
    14: "TSUKUBA CIRCUIT",
    15: "Nürburgring Nordschleife",
    16: "PACIFIC GATEWAY",
    17: "LÖWENSEERING",
    18: "REV CITY",
    20: "SPEEDIAPOLIS RING",
    21: "MYSTIC CAVEWAY",
    22: "EDGE OF THE ROAD",
    23: "DRAGON RANGE",
    26: "AIRPORT SQUARE",
    28: "OCEAN BRIDGE",
    29: "OCEAN BRIDGE",
    30: "MIRAGE CROSSING",
    31: "MIRAGE CROSSING",
    32: "MIRAGE CROSSING",
    33: "MIRAGE CROSSING",
    34: "MIRAGE CROSSING",
    35: "MIRAGE CROSSING",
    36: "MIRAGE CROSSING",
    37: "MIRAGE CROSSING",
    38: "MIRAGE CROSSING",
    39: "MIRAGE CROSSING",
    40: "MIRAGE CROSSING",
    41: "MIRAGE CROSSING",
    42: "MIRAGE CROSSING",
    43: "MIRAGE CROSSING",
    44: "MIRAGE CROSSING",
    45: "MIRAGE CROSSING",
    46: "COSMIC EGGWAY",
    47: "COSMIC WINDING",
    48: "WILD WEST ENDURO",
    99: "GARAGE",
    112: "MARCO STRADA",
    113: "MARCO STRADA",
    114: "Nürburgring Nordschleife",
    115: "MARCO STRADA",
    116: "MIRAGE CROSSING",
    117: "PYLON SLALOM",
    118: "SS CIRCLE",
    119: "DEMO RUN",
    201: "AUTUMN HILL",
    202: "AUTUMN MOUNTAIN",
    203: "VICTORIA GARDEN",
    204: "VICTORIA ROAD",
    205: "ROUTE de la SEINE",
    207: "BURGENSCHLUCHT",
    208: "WINTERTRAUM",
    210: "MARCO STRADA",
    211: "MARCO STRADA",
    212: "TSUKUBA CIRCUIT",
    213: "TSUKUBA CIRCUIT",
    214: "TSUKUBA CIRCUIT",
    215: "Nürburgring Nordschleife",
    216: "PACIFIC GATEWAY",
    217: "LÖWENSEERING",
    218: "REV CITY",
    221: "MYSTIC CAVEWAY",
    222: "EDGE OF THE ROAD",
    223: "DRAGON RANGE",
    247: "COSMIC WINDING",
    248: "WILD WEST ENDURO",
}

# car table at 0x485938: (number, field4, name_jp, name_en), index = car index
CARS = [
    (1, 8, "ユーノスロードスター S-SPECIAL typeⅡ (NA8C)", "EUNOS ROADSTER S-SPECIAL typeⅡ (NA8C)"),
    (2, 8, "マーチ", "MARCH"),
    (3, 9, "ロードスター RS-Ⅱ (NB8C)", "Roadster RS-Ⅱ (NB8C)"),
    (5, 9, "ＮＳＸ タイプＲ (NA2)", "NSX TypeR (NA2)"),
    (6, 8, "ｂＢ", "bB"),
    (7, 8, "２０００ＧＴ", "2000GT"),
    (8, 8, "スープラ RZ (JZA80)", "Supra RZ (JZA80)"),
    (10, 8, "スポーツ８００", "SPORTS 800"),
    (11, 8, "TOYOTA ＧＴ-ｏｎｅ (Race Car)", "TOYOTA GT-one (Race Car)"),
    (13, 8, "フェアレディ 240ZG (S30)", "Fairlady 240ZG (S30)"),
    (14, 8, "ブルーバード 1600 SSS COUPE (510)", "BlueBird 1600 SSS COUPE (510)"),
    (15, 8, "シビック RS", "CIVIC RS"),
    (16, 8, "Ｓ８００", "S800"),
    (17, 9, "MAZDA ７８７Ｂ (Race Car)", "MAZDA 787B (Race Car)"),
    (18, 8, "コスモ スポーツ", "COSMO SPORT"),
    (19, 8, "ギャラン ＧＴＯ MR", "Galant GTO MR"),
    (20, 8, "ｅＫワゴン", "eK@.WAGON"),
    (21, 8, "スバル ヤング SS", "SUBARU YOUNG SS"),
    (25, 8, "1963 コルベット スティング レイ Sport Coupe (C2)", "1963 CORVETTE STING RAY Sport Coupe (C2)"),
    (26, 8, "1966 マスタング GT", "1966 MUSTANG GT"),
    (27, 8, "スプライト MKⅠ", "SPRITE MKⅠ"),
    (28, 8, "ストラトス", "STRATOS"),
    (29, 8, "５ Turbo 2", "5 Turbo 2"),
    (31, 8, "ソアラ 2.5GT ツインターボ", "SOARER 2.5GT-TWINTURBO"),
    (32, 8, "アリスト Ｖ３００ VERTEX EDITION", "ARISTO V300 VERTEX EDITION"),
    (35, 8, "プリウス", "PRIUS"),
    (36, 8, "セルシオ", "CELSIOR"),
    (37, 8, "アルテッツァ RS200", "ALTEZZA RS200"),
    (38, 8, "エスティマ ハイブリッド", "ESTIMA HYBRID"),
    (39, 8, "カローラ 1.8 Luxel", "COROLLA 1.8 Luxel"),
    (40, 8, "ｉｓｔ", "ist"),
    (42, 8, "スカイライン 350GT-8 (V35)", "SKYLINE 350GT-8 (V35)"),
    (45, 8, "ステージア", "STAGEA"),
    (46, 8, "シーマ 450XV", "CIMA 450XV"),
    (47, 8, "インサイト", "insight"),
    (48, 9, "インテグラ TYPE R (DC5)", "INTEGRA TYPE R (DC5)"),
    (49, 8, "シビック タイプＲ (EP3)", "CIVIC TYPE R (EP3)"),
    (50, 8, "インテグラ タイプＲ (DC2)", "INTEGRA TYPE R (DC2)"),
    (51, 8, "Ｓ２０００", "S2000"),
    (52, 8, "オデッセイ アブソルート", "ODYSSEY Absolute"),
    (54, 8, "ＲＸ-７ SPIRIT R (FD3S)", "RX-7 SPIRIT R (FD3S)"),
    (56, 8, "レガシィ ツーリングワゴン GT-B E-tuneⅡ (BH5)", "LEGACY TOURING WAGON GT-B E-tuneⅡ (BH5)"),
    (57, 8, "レガシィ Ｂ４ RSK (BE5)", "LEGACY B4 RSK (BE5)"),
    (58, 8, "フォレスター", "FORESTER"),
    (60, 8, "インプレッサ ＷＲＸ STi Limited (GDB typeⅠ)", "IMPREZA WRX STi Limited (GDB typeⅠ)"),
    (61, 8, "ストーリア Ｘ４", "storia X4"),
    (63, 9, "Ｇ５００Ｌ", "G500L"),
    (64, 8, "Ｃ３２ ＡＭＧ", "C32 AMG"),
    (66, 9, "Ｓ６００Ｌ", "S600L"),
    (67, 8, "ＣＬ５５ ＡＭＧ", "CL55 AMG"),
    (69, 8, "ＳＬ５００", "SL500"),
    (79, 8, "ポロ", "Polo"),
    (82, 8, "オールロード クワトロ 2.7T", "allroad quattro 2.7T"),
    (83, 8, "ＴＴ Roadster 1.8T quattro", "TT Roadster 1.8T quattro"),
    (84, 8, "Ａ４ 3.0 quattro Sport", "A4 3.0 quattro Sport"),
    (85, 8, "ヴィータ GSi", "VITA GSi"),
    (86, 8, "ミニ クーパーＳ", "MINI COOPER S"),
    (87, 8, "2002 カマロ Z28", "2002 CAMARO Z28"),
    (88, 8, "Ｘタイプ 2.5 V6 SPORT", "X-TYPE 2.5 V6 SPORT"),
    (89, 8, "Ｓタイプ Ｒ", "S-TYPE R"),
    (90, 8, "ＸＪＲ 4.0 Supercharged V8", "XJR 4.0 Supercharged V8"),
    (91, 8, "ＳＺ", "SZ"),
    (92, 8, "アルファ スパイダー Quadrifoglio Verde", "Alfa Spider Quadrifoglio Verde"),
    (95, 8, "アルファ １５６ GTA", "Alfa 156 GTA"),
    (97, 8, "アルファ ＧＴＶ 3.2 V6 24V", "Alfa GTV 3.2 V6 24V"),
    (98, 8, "１０６ S16", "106 S16"),
    (100, 8, "２０６ＣＣ S16", "206CC S16"),
    (103, 8, "スマート フォーツー カブリオ", "smart fortwo cabrio"),
    (105, 8, "プリメーラ 20V", "PRIMERA 20V"),
    (106, 8, "アコード ユーロＲ (CL1)", "Accord Euro-R (CL1)"),
    (108, 8, "アテンザ セダン SEDAN 23E", "Atenza SEDAN 23E"),
    (109, 8, "モビリオ", "MOBILIO"),
    (111, 8, "ＸＫＲ 100", "XKR 100"),
    (112, 8, "レンジローバー", "RANGE ROVER"),
    (113, 8, "アテンザ Sport 23Z", "Atenza Sport 23Z"),
    (114, 8, "Ｖ７０ Ｒ", "V70 R"),
    (117, 8, "パジェロ ショート", "PAJERO SHORT"),
    (119, 8, "ＭＲ-Ｓ V EDITION", "MR-S V EDITION"),
    (120, 8, "ファンカーゴ", "FunCargo"),
    (121, 8, "９-５ エアロ 2.3TS", "9-5 Aero 2.3TS"),
    (122, 8, "セビル STS", "SEVILLE STS"),
    (123, 8, "ヴォルツ", "VOLTZ"),
    (124, 8, "アストロ", "ASTRO"),
    (126, 8, "ＰＴクルーザー", "PT Cruiser"),
    (127, 8, "バイパー GTS", "Viper GTS"),
    (129, 8, "ビート", "BEAT"),
    (130, 8, "コペン", "Copen"),
    (132, 8, "ルーテシア ルノー@.スポール2.0 RENAULT F1Team LIMITED Edition", "Clio RENAULT sport2.0"),
    (133, 8, "2002 コルベット Z51 (C5)", "2002 CORVETTE Z51 (C5)"),
    (137, 8, "レガシィ ランカスター６", "LEGACY Lancaster6"),
    (144, 8, "４０６クーペ", "406 Coupe"),
    (146, 8, "Ｓ６０ Ｒ", "S60 R"),
    (148, 8, "ヒュンダイ・クーペ", "HYUNDAI Coupe / TIBURON"),
    (151, 8, "タモーラ", "Tamora"),
    (152, 8, "モコ", "MOCO"),
    (153, 8, "セリカ SS-Ⅱ (ZZT231)", "CELICA SS-Ⅱ (ZZT231)"),
    (154, 8, "サーブラウ 4.5", "Cerbera 4.5"),
    (155, 8, "ＺＺ S coupe", "ZZ S coupe"),
    (156, 8, "ランドクルーザー１００", "LAND CRUISER 100"),
    (157, 8, "エルグランド", "ELGRAND"),
    (158, 8, "NISMO Ｒ３４ スカイライン ＧＴ-Ｒ S-tune", "NISMO R34 SKYLINE GT-R S-tune"),
    (159, 8, "NISMO Ｓ１５ シルビア R-tune", "NISMO S15 SILVIA R-tune"),
    (160, 8, "ウイングロード", "WINGROAD"),
    (161, 8, "サクソ VTS", "Saxo VTS"),
    (163, 8, "フェアレディＺ Version S (Z33)", "FAIRLADY Z Version S (Z33)"),
    (166, 8, "２００２ turbo", "2002 turbo"),
    (167, 8, "アルピーヌ Ａ１１０ 1600SC", "ALPINE A110 1600SC"),
    (168, 8, "２ＣＶ６ Charleston", "2CV6 Charleston"),
    (170, 9, "Ford フォーカス Rally Car", "Ford FOCUS Rally Car"),
    (172, 8, "ＭＲ２ GT-S (SW20)", "MR2 GT-S (SW20)"),
    (173, 8, "TOYOTA エッソウルトラフロー スープラ (Race Car)", "TOYOTA EXXON Superflo Supra (Race Car)"),
    (174, 8, "スプリンター トレノ 3door GT APEX (AE86)", "SPRINTER TRUENO 3door GT APEX (AE86)"),
    (175, 8, "セリカ GT@.FOUR WRC (ST205)", "CELICA GT@.FOUR WRC (ST205)"),
    (176, 8, "１８０ＳＸ TYPE X (RPS13)", "180SX TYPE X (RPS13)"),
    (177, 8, "シルビア K's (S13)", "SILVIA K's (S13)"),
    (179, 8, "スカイライン ＧＴ-Ｒ V@.specⅡ (R32)", "SKYLINE GT-R V@.specⅡ (R32)"),
    (180, 8, "スカイライン ＧＴ-Ｒ V@.specⅡ N@ur (R34)", "SKYLINE GT-R V@.specⅡ N@ur (R34)"),
    (181, 8, "ザナヴィ ニスモ ＧＴ-Ｒ (Race Car)", "XANAVI NISMO GT-R (Race Car)"),
    (183, 8, "SUBARU インプレッサ (Rally Car)", "SUBARU IMPREZA (Rally Car)"),
    (184, 8, "ＮＳＸ type S@.Zero", "NSX type S@.Zero"),
    (186, 8, "HONDA Ｇ'ＺＯＸ－ＮＳＸ (Race Car)", "HONDA G'ZOX-NSX (Race Car)"),
    (187, 8, "シビック タイプＲ (EK9)", "CIVIC TYPE R (EK9)"),
    (188, 8, "SAVANNA ＲＸ-７ ∞ (FC3S)", "SAVANNA RX-7 ∞ (FC3S)"),
    (189, 8, "MITSUBISHI ランサー エボリューション Ⅶ (Rally Car)", "MITSUBISHI LANCER EVOLUTION Ⅶ (Rally Car)"),
    (190, 8, "PEUGEOT ２０６ Rally Car 2000", "PEUGEOT 206 Rally Car 2000"),
    (193, 8, "コブラ 427 S/C", "COBRA 427 S/C"),
    (194, 9, "スーパーセブン SUPERLIGHT R500", "SUPER 7 SUPERLIGHT R500"),
    (197, 8, "ヨーロッパ スペシャル", "EUROPA SPECIAL"),
    (198, 8, "ミニ クーパー 1275S MkⅠ", "MINI COOPER 1275S MkⅠ"),
    (199, 9, "５００ F", "500 F"),
    (200, 8, "ラリー ０３７", "RALLY 037"),
    (201, 8, "スカイライン 2000ＧＴ-Ｒ (KPGC10)", "SKYLINE 2000GT-R (KPGC10)"),
    (203, 9, "インプレッサ ＷＲＸ STi (GDB typeⅡ)", "IMPREZA WRX STi (GDB typeⅡ)"),
    (206, 8, "ＤＢ５ Vantage", "DB5 Vantage"),
    (208, 8, "デロリアン", "DE LOREAN"),
    (209, 8, "エスプリ S2", "esprit S2"),
    (211, 8, "エリーゼ 111S", "ELISE 111S"),
    (212, 8, "パンテーラ GTS", "PANTERA GTS"),
    (215, 8, "Ｚ４ 3.0i", "Z4 3.0i"),
    (216, 8, "1956 ビートル タイプ１", "1956 Beetle Type1"),
    (218, 8, "カプチーノ", "Cappuccino"),
    (222, 8, "スカイライン ＧＴ-Ｒ V@.spec (R33)", "SKYLINE GT-R V@.spec (R33)"),
    (225, 8, "ＲＸ-８ Type S", "RX-8 Type S"),
    (229, 8, "ＤＳ ２３ Pallas", "DS 23 Pallas"),
    (230, 8, "デルタ integrale EVOLUZIONEⅡ", "DELTA integrale EVOLUZIONEⅡ"),
    (231, 8, "エラン S.3 SE", "ELAN S.3 SE"),
    (232, 8, "1973 ファイヤーバード トランザム SD-455", "1973 Firebird TRANS AM SD-455"),
    (233, 8, "キューブ", "cube"),
    (236, 8, "アコード ユーロＲ (CL7)", "ACCORD Euro-R (CL7)"),
    (237, 8, "ランサー GSR EvolutionⅢ", "LANCER GSR EvolutionⅢ"),
    (239, 8, "ランサー エボリューションⅧ GSR", "LANCER EvolutionⅧ GSR"),
    (240, 8, "スカイライン 2000ＧＴ-Ｒ (KPGC110)", "SKYLINE 2000GT-R (KPGC110)"),
    (241, 8, "シティ TURBOⅡ", "CITY TURBOⅡ"),
    (242, 8, "1971 コルベット スティングレイ Coupe (C3)", "1971 CORVETTE Stingray Coupe (C3)"),
    (244, 8, "フィット 1.5T", "Fit 1.5T"),
    (245, 8, "アルファ １４７ GTA", "Alfa 147 GTA"),
    (254, 8, "ＭＧＢ Mk-Ⅰ", "MGB Mk-Ⅰ"),
    (255, 8, "Ｅタイプ 4@.2", "E TYPE 4@.2"),
    (256, 8, "ＴＴ Coupe 3.2 quattro Sline", "TT Coupe 3.2 quattro Sline"),
    (258, 8, "３００ＳＬ", "300SL"),
    (261, 8, "インプレッサ ２２Ｂ STi Version", "Impreza 22B STi Version"),
    (263, 8, "サバンナ ＡＰ GT", "SAVANNA AP GT"),
    (264, 8, "サバンナ ＲＸ-７ GT-X (SA22C)", "SAVANNA RX-7 GT-X (SA22C)"),
    (265, 8, "デミオ", "Demio"),
    (266, 8, "ガライヤ", "Garaiya"),
    (270, 8, "NISSAN Ｒ３９０ GT1 (Race Car)", "NISSAN R390 GT1 (Race Car)"),
    (277, 8, "ゴルフ Ｒ３２ (Ⅳ)", "Golf R32 (Ⅳ)"),
    (279, 8, "ヴィッツ RSターボ", "Vitz RS TURBO"),
    (280, 8, "スカイラインクーペ 350GT プレミアム (V35)", "SKYLINE COUPE 350GT PREMIUM (V35)"),
    (281, 8, "アバルト １３１ラリー", "ABARTH 131 rally"),
    (283, 8, "ニュービートル", "New Beetle"),
    (285, 8, "シルビア spec.R (S15)", "Silvia spec.R (S15)"),
    (286, 8, "ランサー エボリューション Ⅶ GSR", "LANCER EVOLUTION Ⅶ GSR"),
    (290, 8, "ＥＢ１１０", "EB110"),
    (291, 8, "AUDI Ｒ８ TEAM GOH 2003 (Race Car)", "AUDI R8 TEAM GOH 2003 (Race Car)"),
    (292, 8, "Ａ８ 4.2 quattro", "A8 4.2 quattro"),
    (293, 8, "ＲＳ６", "RS6"),
    (295, 8, "V12 ヴァンキッシュ", "V12 VANQUISH"),
    (296, 8, "OPEL アストラ V8 Coupe 24h (Race Car)", "OPEL Astra V8 Coupe 24h (Race Car)"),
    (297, 8, "Ｃ３", "C3"),
    (298, 8, "CITRO@EN クサラ", "CITRO@EN Xsara"),
    (299, 8, "アルファード Ｖ", "ALPHARD V"),
    (300, 8, "2003 サンダーバード", "2003 Thunderbird"),
    (301, 8, "2003 マスタング mach 1", "2003 MUSTANG mach 1"),
    (302, 8, "トゥアレグ V8", "Touareg V8"),
    (304, 8, "Mercedes-Benz CLK-DTM (Race Car)", "Mercedes-Benz CLK-DTM (Race Car)"),
    (305, 8, "コルト", "COLT"),
    (306, 8, "ランサー エボリューションⅥ T.M. EDITION", "LANCER EvolutionⅥ T.M. EDITION"),
    (307, 8, "ＣＴＲ", "CTR"),
    (308, 8, "ＲＧＴ", "RGT"),
    (309, 8, "ｔｕｒｂｏ Ｒ", "turbo R"),
    (310, 8, "アヴァンタイム", "AVANTIME"),
    (311, 8, "シルビア K's エアロ (S14)", "Silvia K's AERO (S14)"),
    (315, 8, "インプレッサ ＷＲＸ STi VersionⅥ (GC8)", "Impreza WRX STi VersionⅥ (GC8)"),
    (316, 8, "ＭＲ２ G-Limited SuperCharger (AW11)", "MR2 G-Limited SuperCharger (AW11)"),
    (319, 8, "ジュリア スプリント GTA", "Giulia Sprint GTA"),
    (320, 8, "アルファ ＧＴ 3.2 V6 24V", "Alfa GT 3.2 V6 24V"),
    (321, 8, "レガシィ Ｂ４ 2.0GT spec.B (BL5)", "LEGACY B4 2.0GT spec.B (BL5)"),
    (323, 8, "2005 ＦＯＲＤ ＧＴ", "2005 FORD GT"),
    (327, 8, "アバルト １０００ＴＣＲ", "ABARTH 1000TCR"),
    (330, 8, "MITSUBISHI パジェロ エボリューション (Rally Car)", "MITSUBISHI PAJERO EVOLUTION (Rally Car)"),
    (331, 8, "NISSAN ピックアップ (Rally Car)", "NISSAN PICK UP (Rally Car)"),
    (332, 8, "ＳＬＲ", "SLR"),
    (333, 8, "ゴルフ ＧＴＩ (Ⅴ)", "Golf GTI (Ⅴ)"),
    (334, 8, "マクラーレンＦ１ GTR (Race Car)", "McLaren F1 GTR (Race Car)"),
    (335, 8, "Ｍ３ GTR road version (E46)", "M3 GTR road version (E46)"),
    (336, 8, "BMW ３.０ ＣＳＬ (Race Car)", "BMW 3.0 CSL (Race Car)"),
    (337, 8, "BMW Ｍ１ procar (Race Car)", "BMW M1 procar (Race Car)"),
    (338, 8, "Ｍ３ SPORT EVOLUTION (E30)", "M3 SPORT EVOLUTION (E30)"),
    (353, 8, "2005 マスタング GT", "2005 MUSTANG GT"),
    (354, 8, "AUDI Ｒ８ TEAM GOH 2004 (Race Car)", "AUDI R8 TEAM GOH 2004 (Race Car)"),
]

# synthetic car numbers past the table (0x1DAB78)
CAR_SYNTH_LO, CAR_SYNTH_LO_BASE = 211, 9999789      # idx 211..220 -> 10000000..10000009
CAR_SYNTH_HI, CAR_SYNTH_HI_BASE = 221, 19999779     # idx 221+ -> 20000000+

# payload signatures: magic -> (extension, description, offset of a declared-size u32 or None)
SIGNATURES = {
    b"\x87\xfc\x00\x10": ("pkd",  "nested archive, 16-byte aligned entries", None),
    b"SDAT":             ("sdat", "sound bank / sequence data", None),
    b"TUTO":             ("tuto", "tutorial script data", None),
    b"LP  ":             ("lp",   "streamed audio, 48 kHz, 2 ch", 4),
    b"AP  ":             ("ap",   "streamed audio, 44.1 kHz", 4),
    b"LEP ":             ("lep",  "streamed audio variant", 4),
    b"ABCD":             ("abcd", "texture / GS upload container", None),
    b"PC\x00\x04":       ("pc",   "scene container (holds BGnn sub-chunks)", None),
    b"\xff\xff\xfeE":    ("str",  "chunked stream, 0x4000-byte chunks", None),
    b"\x00\x00\x01\x00": ("ico",  "PS2 memory-card icon", None),
}
DEFAULT_EXT = "bin"


def build_layout():
    out, base = [], 0
    for count, path, cls, in_arc, rule in GROUPS:
        out.append((base, base + count - 1, count, path, cls, in_arc, rule))
        base += count
    return out, base


LAYOUT, TOTAL_SLOTS = build_layout()


def group_of(fid):
    for entry in LAYOUT:
        if entry[0] <= fid <= entry[1]:
            return entry
    return None


def read_toc(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if len(raw) % 4:
        raise ValueError("%s: length %d is not a multiple of 4" % (path, len(raw)))
    return list(struct.unpack("<%dI" % (len(raw) // 4), raw))


def classify(head):
    for magic, info in SIGNATURES.items():
        if head.startswith(magic):
            return info
    return (DEFAULT_EXT, "", None)


def parse_pkd(blob):
    """parse a 0x1000FC87 nested archive -> [(start, size), ...] or None"""
    if len(blob) < 16 or blob[:4] != b"\x87\xfc\x00\x10":
        return None
    count, data_start = struct.unpack_from("<2I", blob, 8)
    if count < 1 or 8 + count * 8 > len(blob) or data_start > len(blob):
        return None
    if data_start < 8 + count * 8:
        return None
    entries, prev_end = [], data_start
    for k in range(1, count):
        size, end = struct.unpack_from("<2I", blob, 8 + k * 8)
        if end > len(blob) or end < prev_end or prev_end + size > len(blob):
            return None
        if ((prev_end + size + 15) & ~15) != end:
            return None
        entries.append((prev_end, size))
        prev_end = end
    return entries


def load_cbd_numbers(fh, toc):
    """car numbers in index order, read from all_cbd.bin (slot 108), [] if unreadable"""
    if ALL_CBD_FID + 1 >= len(toc) or toc[ALL_CBD_FID] == toc[ALL_CBD_FID + 1]:
        return []
    fh.seek(toc[ALL_CBD_FID] * SECTOR)
    blob = fh.read((toc[ALL_CBD_FID + 1] - toc[ALL_CBD_FID]) * SECTOR)
    entries = parse_pkd(blob)
    if not entries or any(size < 8 for _off, size in entries):
        return []
    numbers = [struct.unpack_from("<I", blob, off + 4)[0] for off, _size in entries]
    if any(a >= b for a, b in zip(numbers, numbers[1:])):
        return []          # game expects them strictly ascending
    return numbers


def safe_name(name, ascii_only):
    """filesystem-safe form of a game name"""
    s = unicodedata.normalize("NFKC", name)      # full-width -> ASCII, roman numerals -> II etc
    if ascii_only:
        s = s.replace("∞", "Infini")        # SAVANNA RX-7 trim
    s = s.replace("/", "-")
    s = "".join(c for c in s if c not in '\\:*?"<>|' and ord(c) >= 0x20)
    if ascii_only:
        s = s.encode("ascii", "ignore").decode("ascii")
    return " ".join(s.split()).strip(" .")


def map_name(number):
    """display name of map number NNN, None if the game has none"""
    if 600 <= number < 720 or 800 <= number < 920:
        number -= 600              # mode-dependent variants (0x197590)
    return MAP_NAMES.get(number)


def map_file_name(number):
    name = map_name(number)
    if not name:
        return None
    # file names stay ASCII: Nürburgring -> Nurburgring
    s = "".join(c for c in unicodedata.normalize("NFKD", name)
                if not unicodedata.combining(c))
    return safe_name(s, ascii_only=True) or None


class CarNames:
    """car index -> number and file name"""

    def __init__(self, cbd_numbers, lang):
        table = [r[0] for r in CARS]
        self.warning = None
        self.use_table = not cbd_numbers or table[:len(cbd_numbers)] == cbd_numbers
        if self.use_table:
            self.numbers = dict(enumerate(table))
        else:
            # different game build: keep its numbers, names would not line up
            self.numbers = dict(enumerate(cbd_numbers))
            self.warning = ("all_cbd.bin does not match the built-in car table, "
                            "car files are named by number only")
        self.names = {}
        if self.use_table and lang != "off":
            for i, (_num, _f4, jp, en) in enumerate(CARS):
                nm = safe_name(en if lang == "en" else jp, ascii_only=(lang == "en"))
                if nm:
                    self.names[i] = nm

    def number(self, idx):
        if idx in self.numbers:
            return self.numbers[idx]
        if CAR_SYNTH_LO <= idx < CAR_SYNTH_HI:
            return CAR_SYNTH_LO_BASE + idx
        if idx >= CAR_SYNTH_HI:
            return CAR_SYNTH_HI_BASE + idx
        return None


def slot_name(fid, ext, cars, map_names):
    g = group_of(fid)
    if g is None:
        return "%04d.%s" % (fid, ext)
    idx, gdir, rule = fid - g[0], g[3], g[6]

    if rule == "list":
        names = GROUP_FILE_NAMES.get(gdir)
        if names and idx < len(names):
            return names[idx]
    elif rule == "car_index":
        n = cars.number(idx)
        if n is not None:
            nm = cars.names.get(idx)
            if nm:
                return "%08d_%s.%s" % (n, nm, ext)
            return "%08d.%s" % (n, ext)
    elif rule == "course_index":
        if idx < len(COURSE_NUMBERS):
            n = COURSE_NUMBERS[idx]
            nm = map_file_name(n) if map_names else None
            if nm:
                return "%03d_00_%s.%s" % (n, nm, ext)
            return "%03d_00.%s" % (n, ext)
    elif rule == "course_number":
        nm = map_file_name(idx) if map_names else None
        if nm:
            return "%03d_%s.%s" % (idx, nm, ext)
        return "%03d.%s" % (idx, ext)
    elif rule == "bgm":
        return "bgm%05d.%s" % (idx, ext)
    elif rule == "tutorial":
        return "tutorial%03d.%s" % (idx, ext)
    return "%04d.%s" % (idx, ext)


def copy_range(src, dst_path, offset, length):
    src.seek(offset)
    remaining = length
    with open(dst_path, "wb") as out:
        while remaining > 0:
            chunk = src.read(min(COPY_CHUNK, remaining))
            if not chunk:
                break
            out.write(chunk)
            remaining -= len(chunk)
    return length - remaining


def write_cars_csv(path, cars):
    """one row per car table record, with the archive slots using its index in each car group"""
    car_groups = [(e[3], e[0], e[2]) for e in LAYOUT if e[6] == "car_index"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["index", "number", "name_en", "name_jp", "field4"]
                   + ["fid_" + g.split("/")[-1] for g, _b, _c in car_groups])
        for i, (num, f4, jp, en) in enumerate(CARS):
            w.writerow([i, num, en, jp, f4]
                       + [base + i if i < count else "" for _g, base, count in car_groups])


def extract(toc, data_path, outdir, car_lang, map_names, verbose):
    os.makedirs(outdir, exist_ok=True)
    written = 0
    with open(data_path, "rb") as fh, \
            open(os.path.join(outdir, "manifest.csv"), "w", newline="", encoding="utf-8") as mf:
        cars = CarNames(load_cbd_numbers(fh, toc), car_lang)
        if cars.warning:
            print("WARNING: %s" % cars.warning, file=sys.stderr)
        if cars.use_table:
            write_cars_csv(os.path.join(outdir, "cars.csv"), cars)
        w = csv.writer(mf)
        w.writerow(["fid", "group", "index_in_group", "lba", "sectors", "size",
                    "declared_size", "type", "path", "car_number", "car_name", "map_name"])

        for i in range(len(toc) - 1):
            lba, nsec = toc[i], toc[i + 1] - toc[i]
            if nsec == 0:
                continue
            g = group_of(i)
            gname = g[3] if g else "unknown"
            gidx = i - g[0] if g else ""
            size = nsec * SECTOR
            fh.seek(lba * SECTOR)
            ext, _desc, size_off = classify(fh.read(min(16, size)))
            declared = ""
            if size_off is not None and size >= size_off + 4:
                fh.seek(lba * SECTOR + size_off)
                declared = struct.unpack("<I", fh.read(4))[0]

            subdir = os.path.join(outdir, *gname.split("/"))
            name = slot_name(i, ext, cars, map_names)
            os.makedirs(subdir, exist_ok=True)
            dst = os.path.join(subdir, name)
            copy_range(fh, dst, lba * SECTOR, size)
            written += 1
            if verbose:
                print(os.path.relpath(dst, outdir))

            car_num = car_nm = map_nm = ""
            if g and g[6] == "car_index":
                n = cars.number(gidx)
                car_num = "" if n is None else n
                if cars.use_table and car_lang != "off" and gidx < len(CARS):
                    car_nm = CARS[gidx][3 if car_lang == "en" else 2]
            elif g and g[6] in ("course_index", "course_number"):
                num = gidx if g[6] == "course_number" else (
                    COURSE_NUMBERS[gidx] if gidx < len(COURSE_NUMBERS) else None)
                map_nm = (map_name(num) or "") if num is not None else ""
            w.writerow([i, gname, gidx, lba, nsec, size, declared, ext,
                        os.path.relpath(dst, outdir).replace(os.sep, "/"),
                        car_num, car_nm, map_nm])
    return written


def find_ci(folder, name):
    """path of name inside folder, ignoring case, or None"""
    try:
        for entry in os.listdir(folder):
            if entry.lower() == name.lower():
                return os.path.join(folder, entry)
    except OSError:
        pass
    return None


def find_archive(folder):
    """(D000.BIN, D001.BIN) in folder or in its ENTHUSIA subfolder"""
    sub = find_ci(folder, "ENTHUSIA")
    for d in (folder, sub):
        if d and os.path.isdir(d):
            toc, data = find_ci(d, "D000.BIN"), find_ci(d, "D001.BIN")
            if toc and data and os.path.isfile(toc) and os.path.isfile(data):
                return toc, data
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Extract the D000.BIN / D001.BIN archive of Enthusia Professional Racing (PS2).")
    ap.add_argument("path", help="Enthusia folder holding D000.BIN and D001.BIN (or the disc root)")
    ap.add_argument("-o", "--output",
                    help="output folder (default: %s inside the input folder)" % OUTPUT_DIR_NAME)
    ap.add_argument("--car-names", choices=("en", "jp", "off"), default="en",
                    help="car file names: English (default), Japanese, or numbers only")
    ap.add_argument("--map-names", choices=("on", "off"), default="on",
                    help="add the track name to map files (default: on)")
    ap.add_argument("-v", "--verbose", action="store_true", help="list every extracted file")
    args = ap.parse_args()

    folder = os.path.abspath(args.path)
    if os.path.isfile(folder):
        folder = os.path.dirname(folder)
    found = find_archive(folder)
    if not found:
        sys.exit("D000.BIN / D001.BIN not found in %s" % folder)
    toc_path, data_path = found
    outdir = os.path.abspath(args.output) if args.output else os.path.join(folder, OUTPUT_DIR_NAME)

    toc = read_toc(toc_path)
    if len(toc) - 1 != TOTAL_SLOTS:
        print("WARNING: archive has %d slots but the built-in layout describes %d, "
              "folder names may be wrong (other region or revision?)"
              % (len(toc) - 1, TOTAL_SLOTS), file=sys.stderr)
    data_size = os.path.getsize(data_path)
    if toc[-1] * SECTOR != data_size:
        print("WARNING: D000.BIN expects %d bytes of data, D001.BIN has %d"
              % (toc[-1] * SECTOR, data_size), file=sys.stderr)

    print("extracting %s" % os.path.dirname(toc_path))
    written = extract(toc, data_path, outdir, args.car_names, args.map_names == "on",
                      args.verbose)
    print("wrote %d files to %s" % (written, outdir))


if __name__ == "__main__":
    main()
