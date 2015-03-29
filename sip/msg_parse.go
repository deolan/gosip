
//line msg_parse.rl:1
// -*-go-*-

package sip

import (
	"errors"
	"fmt"
	"github.com/jart/gosip/sdp"
)


//line msg_parse.rl:12

//line msg_parse.go:17
const msg_start int = 1
const msg_first_final int = 542
const msg_error int = 0

const msg_en_value int = 34
const msg_en_xheader int = 44
const msg_en_header int = 51
const msg_en_main int = 1


//line msg_parse.rl:13

// ParseMsg turns a SIP message into a data structure.
func ParseMsg(s string) (msg *Msg, err error) {
	if s == "" {
		return nil, errors.New("Empty SIP message")
	}
	return ParseMsgBytes([]byte(s))
}

// ParseMsg turns a SIP message byte slice into a data structure.
func ParseMsgBytes(data []byte) (msg *Msg, err error) {
	if data == nil {
		return nil, nil
	}
	msg = new(Msg)
	viap := &msg.Via
	cs := 0
	p := 0
	pe := len(data)
	eof := len(data)
	line := 1
	linep := 0
	buf := make([]byte, len(data))
	amt := 0
	mark := 0
	clen := 0
	ctype := ""
	var name string
	var hex byte
	var value *string
	var addr **Addr

	
//line msg_parse.go:62
	{
	cs = msg_start
	}

//line msg_parse.go:67
	{
	var _widec int16
	if p == pe {
		goto _test_eof
	}
	switch cs {
	case 1:
		goto st_case_1
	case 0:
		goto st_case_0
	case 2:
		goto st_case_2
	case 3:
		goto st_case_3
	case 4:
		goto st_case_4
	case 5:
		goto st_case_5
	case 6:
		goto st_case_6
	case 7:
		goto st_case_7
	case 8:
		goto st_case_8
	case 9:
		goto st_case_9
	case 10:
		goto st_case_10
	case 11:
		goto st_case_11
	case 12:
		goto st_case_12
	case 13:
		goto st_case_13
	case 542:
		goto st_case_542
	case 14:
		goto st_case_14
	case 15:
		goto st_case_15
	case 16:
		goto st_case_16
	case 17:
		goto st_case_17
	case 18:
		goto st_case_18
	case 19:
		goto st_case_19
	case 20:
		goto st_case_20
	case 21:
		goto st_case_21
	case 22:
		goto st_case_22
	case 23:
		goto st_case_23
	case 24:
		goto st_case_24
	case 25:
		goto st_case_25
	case 26:
		goto st_case_26
	case 27:
		goto st_case_27
	case 28:
		goto st_case_28
	case 29:
		goto st_case_29
	case 30:
		goto st_case_30
	case 31:
		goto st_case_31
	case 32:
		goto st_case_32
	case 33:
		goto st_case_33
	case 34:
		goto st_case_34
	case 35:
		goto st_case_35
	case 36:
		goto st_case_36
	case 37:
		goto st_case_37
	case 38:
		goto st_case_38
	case 39:
		goto st_case_39
	case 40:
		goto st_case_40
	case 41:
		goto st_case_41
	case 543:
		goto st_case_543
	case 42:
		goto st_case_42
	case 43:
		goto st_case_43
	case 44:
		goto st_case_44
	case 45:
		goto st_case_45
	case 46:
		goto st_case_46
	case 47:
		goto st_case_47
	case 544:
		goto st_case_544
	case 48:
		goto st_case_48
	case 49:
		goto st_case_49
	case 50:
		goto st_case_50
	case 51:
		goto st_case_51
	case 52:
		goto st_case_52
	case 545:
		goto st_case_545
	case 53:
		goto st_case_53
	case 54:
		goto st_case_54
	case 55:
		goto st_case_55
	case 56:
		goto st_case_56
	case 57:
		goto st_case_57
	case 58:
		goto st_case_58
	case 59:
		goto st_case_59
	case 60:
		goto st_case_60
	case 61:
		goto st_case_61
	case 62:
		goto st_case_62
	case 63:
		goto st_case_63
	case 64:
		goto st_case_64
	case 65:
		goto st_case_65
	case 66:
		goto st_case_66
	case 67:
		goto st_case_67
	case 68:
		goto st_case_68
	case 69:
		goto st_case_69
	case 70:
		goto st_case_70
	case 71:
		goto st_case_71
	case 72:
		goto st_case_72
	case 73:
		goto st_case_73
	case 74:
		goto st_case_74
	case 75:
		goto st_case_75
	case 76:
		goto st_case_76
	case 77:
		goto st_case_77
	case 78:
		goto st_case_78
	case 79:
		goto st_case_79
	case 80:
		goto st_case_80
	case 81:
		goto st_case_81
	case 82:
		goto st_case_82
	case 83:
		goto st_case_83
	case 84:
		goto st_case_84
	case 85:
		goto st_case_85
	case 86:
		goto st_case_86
	case 87:
		goto st_case_87
	case 88:
		goto st_case_88
	case 89:
		goto st_case_89
	case 90:
		goto st_case_90
	case 91:
		goto st_case_91
	case 92:
		goto st_case_92
	case 93:
		goto st_case_93
	case 94:
		goto st_case_94
	case 95:
		goto st_case_95
	case 96:
		goto st_case_96
	case 97:
		goto st_case_97
	case 98:
		goto st_case_98
	case 99:
		goto st_case_99
	case 100:
		goto st_case_100
	case 101:
		goto st_case_101
	case 102:
		goto st_case_102
	case 103:
		goto st_case_103
	case 104:
		goto st_case_104
	case 105:
		goto st_case_105
	case 106:
		goto st_case_106
	case 107:
		goto st_case_107
	case 108:
		goto st_case_108
	case 109:
		goto st_case_109
	case 110:
		goto st_case_110
	case 111:
		goto st_case_111
	case 112:
		goto st_case_112
	case 113:
		goto st_case_113
	case 114:
		goto st_case_114
	case 115:
		goto st_case_115
	case 116:
		goto st_case_116
	case 117:
		goto st_case_117
	case 118:
		goto st_case_118
	case 119:
		goto st_case_119
	case 120:
		goto st_case_120
	case 121:
		goto st_case_121
	case 122:
		goto st_case_122
	case 123:
		goto st_case_123
	case 124:
		goto st_case_124
	case 125:
		goto st_case_125
	case 126:
		goto st_case_126
	case 127:
		goto st_case_127
	case 128:
		goto st_case_128
	case 129:
		goto st_case_129
	case 130:
		goto st_case_130
	case 131:
		goto st_case_131
	case 132:
		goto st_case_132
	case 133:
		goto st_case_133
	case 134:
		goto st_case_134
	case 135:
		goto st_case_135
	case 136:
		goto st_case_136
	case 137:
		goto st_case_137
	case 138:
		goto st_case_138
	case 139:
		goto st_case_139
	case 140:
		goto st_case_140
	case 141:
		goto st_case_141
	case 142:
		goto st_case_142
	case 143:
		goto st_case_143
	case 144:
		goto st_case_144
	case 145:
		goto st_case_145
	case 146:
		goto st_case_146
	case 147:
		goto st_case_147
	case 148:
		goto st_case_148
	case 149:
		goto st_case_149
	case 150:
		goto st_case_150
	case 151:
		goto st_case_151
	case 152:
		goto st_case_152
	case 153:
		goto st_case_153
	case 154:
		goto st_case_154
	case 155:
		goto st_case_155
	case 156:
		goto st_case_156
	case 157:
		goto st_case_157
	case 158:
		goto st_case_158
	case 159:
		goto st_case_159
	case 160:
		goto st_case_160
	case 161:
		goto st_case_161
	case 162:
		goto st_case_162
	case 163:
		goto st_case_163
	case 164:
		goto st_case_164
	case 165:
		goto st_case_165
	case 166:
		goto st_case_166
	case 167:
		goto st_case_167
	case 168:
		goto st_case_168
	case 169:
		goto st_case_169
	case 170:
		goto st_case_170
	case 171:
		goto st_case_171
	case 172:
		goto st_case_172
	case 173:
		goto st_case_173
	case 174:
		goto st_case_174
	case 175:
		goto st_case_175
	case 176:
		goto st_case_176
	case 177:
		goto st_case_177
	case 178:
		goto st_case_178
	case 179:
		goto st_case_179
	case 180:
		goto st_case_180
	case 181:
		goto st_case_181
	case 182:
		goto st_case_182
	case 183:
		goto st_case_183
	case 184:
		goto st_case_184
	case 185:
		goto st_case_185
	case 186:
		goto st_case_186
	case 187:
		goto st_case_187
	case 188:
		goto st_case_188
	case 189:
		goto st_case_189
	case 190:
		goto st_case_190
	case 191:
		goto st_case_191
	case 192:
		goto st_case_192
	case 193:
		goto st_case_193
	case 194:
		goto st_case_194
	case 195:
		goto st_case_195
	case 196:
		goto st_case_196
	case 197:
		goto st_case_197
	case 198:
		goto st_case_198
	case 199:
		goto st_case_199
	case 200:
		goto st_case_200
	case 201:
		goto st_case_201
	case 202:
		goto st_case_202
	case 203:
		goto st_case_203
	case 204:
		goto st_case_204
	case 205:
		goto st_case_205
	case 206:
		goto st_case_206
	case 207:
		goto st_case_207
	case 208:
		goto st_case_208
	case 209:
		goto st_case_209
	case 210:
		goto st_case_210
	case 211:
		goto st_case_211
	case 212:
		goto st_case_212
	case 213:
		goto st_case_213
	case 214:
		goto st_case_214
	case 215:
		goto st_case_215
	case 216:
		goto st_case_216
	case 217:
		goto st_case_217
	case 218:
		goto st_case_218
	case 219:
		goto st_case_219
	case 220:
		goto st_case_220
	case 221:
		goto st_case_221
	case 222:
		goto st_case_222
	case 223:
		goto st_case_223
	case 224:
		goto st_case_224
	case 225:
		goto st_case_225
	case 226:
		goto st_case_226
	case 227:
		goto st_case_227
	case 228:
		goto st_case_228
	case 229:
		goto st_case_229
	case 230:
		goto st_case_230
	case 231:
		goto st_case_231
	case 232:
		goto st_case_232
	case 233:
		goto st_case_233
	case 234:
		goto st_case_234
	case 235:
		goto st_case_235
	case 236:
		goto st_case_236
	case 237:
		goto st_case_237
	case 238:
		goto st_case_238
	case 239:
		goto st_case_239
	case 240:
		goto st_case_240
	case 241:
		goto st_case_241
	case 242:
		goto st_case_242
	case 243:
		goto st_case_243
	case 244:
		goto st_case_244
	case 245:
		goto st_case_245
	case 246:
		goto st_case_246
	case 247:
		goto st_case_247
	case 248:
		goto st_case_248
	case 249:
		goto st_case_249
	case 250:
		goto st_case_250
	case 251:
		goto st_case_251
	case 252:
		goto st_case_252
	case 253:
		goto st_case_253
	case 254:
		goto st_case_254
	case 255:
		goto st_case_255
	case 256:
		goto st_case_256
	case 257:
		goto st_case_257
	case 258:
		goto st_case_258
	case 259:
		goto st_case_259
	case 260:
		goto st_case_260
	case 261:
		goto st_case_261
	case 262:
		goto st_case_262
	case 263:
		goto st_case_263
	case 264:
		goto st_case_264
	case 265:
		goto st_case_265
	case 266:
		goto st_case_266
	case 267:
		goto st_case_267
	case 268:
		goto st_case_268
	case 269:
		goto st_case_269
	case 270:
		goto st_case_270
	case 271:
		goto st_case_271
	case 272:
		goto st_case_272
	case 273:
		goto st_case_273
	case 274:
		goto st_case_274
	case 275:
		goto st_case_275
	case 276:
		goto st_case_276
	case 277:
		goto st_case_277
	case 278:
		goto st_case_278
	case 279:
		goto st_case_279
	case 280:
		goto st_case_280
	case 281:
		goto st_case_281
	case 282:
		goto st_case_282
	case 283:
		goto st_case_283
	case 284:
		goto st_case_284
	case 285:
		goto st_case_285
	case 286:
		goto st_case_286
	case 287:
		goto st_case_287
	case 288:
		goto st_case_288
	case 289:
		goto st_case_289
	case 290:
		goto st_case_290
	case 291:
		goto st_case_291
	case 292:
		goto st_case_292
	case 293:
		goto st_case_293
	case 294:
		goto st_case_294
	case 295:
		goto st_case_295
	case 296:
		goto st_case_296
	case 297:
		goto st_case_297
	case 298:
		goto st_case_298
	case 299:
		goto st_case_299
	case 300:
		goto st_case_300
	case 301:
		goto st_case_301
	case 302:
		goto st_case_302
	case 303:
		goto st_case_303
	case 304:
		goto st_case_304
	case 305:
		goto st_case_305
	case 306:
		goto st_case_306
	case 307:
		goto st_case_307
	case 308:
		goto st_case_308
	case 309:
		goto st_case_309
	case 310:
		goto st_case_310
	case 311:
		goto st_case_311
	case 312:
		goto st_case_312
	case 313:
		goto st_case_313
	case 314:
		goto st_case_314
	case 315:
		goto st_case_315
	case 316:
		goto st_case_316
	case 317:
		goto st_case_317
	case 318:
		goto st_case_318
	case 319:
		goto st_case_319
	case 320:
		goto st_case_320
	case 321:
		goto st_case_321
	case 322:
		goto st_case_322
	case 323:
		goto st_case_323
	case 324:
		goto st_case_324
	case 325:
		goto st_case_325
	case 326:
		goto st_case_326
	case 327:
		goto st_case_327
	case 328:
		goto st_case_328
	case 329:
		goto st_case_329
	case 330:
		goto st_case_330
	case 331:
		goto st_case_331
	case 332:
		goto st_case_332
	case 333:
		goto st_case_333
	case 334:
		goto st_case_334
	case 335:
		goto st_case_335
	case 336:
		goto st_case_336
	case 337:
		goto st_case_337
	case 338:
		goto st_case_338
	case 339:
		goto st_case_339
	case 340:
		goto st_case_340
	case 341:
		goto st_case_341
	case 342:
		goto st_case_342
	case 343:
		goto st_case_343
	case 344:
		goto st_case_344
	case 345:
		goto st_case_345
	case 346:
		goto st_case_346
	case 347:
		goto st_case_347
	case 348:
		goto st_case_348
	case 349:
		goto st_case_349
	case 350:
		goto st_case_350
	case 351:
		goto st_case_351
	case 352:
		goto st_case_352
	case 353:
		goto st_case_353
	case 354:
		goto st_case_354
	case 355:
		goto st_case_355
	case 356:
		goto st_case_356
	case 357:
		goto st_case_357
	case 358:
		goto st_case_358
	case 359:
		goto st_case_359
	case 360:
		goto st_case_360
	case 361:
		goto st_case_361
	case 362:
		goto st_case_362
	case 363:
		goto st_case_363
	case 364:
		goto st_case_364
	case 365:
		goto st_case_365
	case 366:
		goto st_case_366
	case 367:
		goto st_case_367
	case 368:
		goto st_case_368
	case 369:
		goto st_case_369
	case 370:
		goto st_case_370
	case 371:
		goto st_case_371
	case 372:
		goto st_case_372
	case 373:
		goto st_case_373
	case 374:
		goto st_case_374
	case 375:
		goto st_case_375
	case 376:
		goto st_case_376
	case 377:
		goto st_case_377
	case 378:
		goto st_case_378
	case 379:
		goto st_case_379
	case 380:
		goto st_case_380
	case 381:
		goto st_case_381
	case 382:
		goto st_case_382
	case 383:
		goto st_case_383
	case 384:
		goto st_case_384
	case 385:
		goto st_case_385
	case 386:
		goto st_case_386
	case 387:
		goto st_case_387
	case 388:
		goto st_case_388
	case 389:
		goto st_case_389
	case 390:
		goto st_case_390
	case 391:
		goto st_case_391
	case 392:
		goto st_case_392
	case 393:
		goto st_case_393
	case 394:
		goto st_case_394
	case 395:
		goto st_case_395
	case 396:
		goto st_case_396
	case 397:
		goto st_case_397
	case 398:
		goto st_case_398
	case 399:
		goto st_case_399
	case 400:
		goto st_case_400
	case 401:
		goto st_case_401
	case 402:
		goto st_case_402
	case 403:
		goto st_case_403
	case 404:
		goto st_case_404
	case 405:
		goto st_case_405
	case 406:
		goto st_case_406
	case 407:
		goto st_case_407
	case 408:
		goto st_case_408
	case 409:
		goto st_case_409
	case 410:
		goto st_case_410
	case 411:
		goto st_case_411
	case 412:
		goto st_case_412
	case 413:
		goto st_case_413
	case 414:
		goto st_case_414
	case 415:
		goto st_case_415
	case 416:
		goto st_case_416
	case 417:
		goto st_case_417
	case 418:
		goto st_case_418
	case 419:
		goto st_case_419
	case 420:
		goto st_case_420
	case 421:
		goto st_case_421
	case 422:
		goto st_case_422
	case 423:
		goto st_case_423
	case 424:
		goto st_case_424
	case 425:
		goto st_case_425
	case 426:
		goto st_case_426
	case 427:
		goto st_case_427
	case 428:
		goto st_case_428
	case 429:
		goto st_case_429
	case 430:
		goto st_case_430
	case 431:
		goto st_case_431
	case 432:
		goto st_case_432
	case 433:
		goto st_case_433
	case 434:
		goto st_case_434
	case 435:
		goto st_case_435
	case 436:
		goto st_case_436
	case 437:
		goto st_case_437
	case 438:
		goto st_case_438
	case 439:
		goto st_case_439
	case 440:
		goto st_case_440
	case 441:
		goto st_case_441
	case 442:
		goto st_case_442
	case 443:
		goto st_case_443
	case 444:
		goto st_case_444
	case 445:
		goto st_case_445
	case 446:
		goto st_case_446
	case 447:
		goto st_case_447
	case 448:
		goto st_case_448
	case 449:
		goto st_case_449
	case 450:
		goto st_case_450
	case 451:
		goto st_case_451
	case 452:
		goto st_case_452
	case 453:
		goto st_case_453
	case 454:
		goto st_case_454
	case 455:
		goto st_case_455
	case 456:
		goto st_case_456
	case 457:
		goto st_case_457
	case 458:
		goto st_case_458
	case 459:
		goto st_case_459
	case 460:
		goto st_case_460
	case 461:
		goto st_case_461
	case 462:
		goto st_case_462
	case 463:
		goto st_case_463
	case 464:
		goto st_case_464
	case 465:
		goto st_case_465
	case 466:
		goto st_case_466
	case 467:
		goto st_case_467
	case 468:
		goto st_case_468
	case 469:
		goto st_case_469
	case 470:
		goto st_case_470
	case 471:
		goto st_case_471
	case 472:
		goto st_case_472
	case 473:
		goto st_case_473
	case 474:
		goto st_case_474
	case 475:
		goto st_case_475
	case 476:
		goto st_case_476
	case 477:
		goto st_case_477
	case 478:
		goto st_case_478
	case 479:
		goto st_case_479
	case 480:
		goto st_case_480
	case 481:
		goto st_case_481
	case 482:
		goto st_case_482
	case 483:
		goto st_case_483
	case 484:
		goto st_case_484
	case 485:
		goto st_case_485
	case 486:
		goto st_case_486
	case 487:
		goto st_case_487
	case 488:
		goto st_case_488
	case 489:
		goto st_case_489
	case 490:
		goto st_case_490
	case 491:
		goto st_case_491
	case 492:
		goto st_case_492
	case 493:
		goto st_case_493
	case 494:
		goto st_case_494
	case 495:
		goto st_case_495
	case 496:
		goto st_case_496
	case 497:
		goto st_case_497
	case 498:
		goto st_case_498
	case 499:
		goto st_case_499
	case 500:
		goto st_case_500
	case 501:
		goto st_case_501
	case 502:
		goto st_case_502
	case 503:
		goto st_case_503
	case 504:
		goto st_case_504
	case 505:
		goto st_case_505
	case 506:
		goto st_case_506
	case 507:
		goto st_case_507
	case 508:
		goto st_case_508
	case 509:
		goto st_case_509
	case 510:
		goto st_case_510
	case 511:
		goto st_case_511
	case 512:
		goto st_case_512
	case 513:
		goto st_case_513
	case 514:
		goto st_case_514
	case 515:
		goto st_case_515
	case 516:
		goto st_case_516
	case 517:
		goto st_case_517
	case 518:
		goto st_case_518
	case 519:
		goto st_case_519
	case 520:
		goto st_case_520
	case 521:
		goto st_case_521
	case 522:
		goto st_case_522
	case 523:
		goto st_case_523
	case 524:
		goto st_case_524
	case 525:
		goto st_case_525
	case 526:
		goto st_case_526
	case 527:
		goto st_case_527
	case 528:
		goto st_case_528
	case 529:
		goto st_case_529
	case 530:
		goto st_case_530
	case 531:
		goto st_case_531
	case 532:
		goto st_case_532
	case 533:
		goto st_case_533
	case 534:
		goto st_case_534
	case 535:
		goto st_case_535
	case 536:
		goto st_case_536
	case 537:
		goto st_case_537
	case 538:
		goto st_case_538
	case 539:
		goto st_case_539
	case 540:
		goto st_case_540
	case 541:
		goto st_case_541
	}
	goto st_out
	st_case_1:
		switch data[p] {
		case 33:
			goto tr0
		case 37:
			goto tr0
		case 39:
			goto tr0
		case 83:
			goto tr2
		case 126:
			goto tr0
		}
		switch {
		case data[p] < 48:
			switch {
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 46 {
					goto tr0
				}
			case data[p] >= 42:
				goto tr0
			}
		case data[p] > 57:
			switch {
			case data[p] > 90:
				if 95 <= data[p] && data[p] <= 122 {
					goto tr0
				}
			case data[p] >= 65:
				goto tr0
			}
		default:
			goto tr0
		}
		goto st0
tr73:
//line msg_parse.rl:131

			p--

			{goto st44 }
		
//line msg_parse.rl:125

			p--

			{goto st44 }
		
	goto st0
tr105:
//line msg_parse.rl:125

			p--

			{goto st44 }
		
	goto st0
tr293:
//line msg_parse.rl:131

			p--

			{goto st44 }
		
	goto st0
//line msg_parse.go:1234
st_case_0:
	st0:
		cs = 0
		goto _out
tr0:
//line msg_parse.rl:55

			mark = p
		
	goto st2
	st2:
		if p++; p == pe {
			goto _test_eof2
		}
	st_case_2:
//line msg_parse.go:1250
		switch data[p] {
		case 32:
			goto tr3
		case 33:
			goto st2
		case 37:
			goto st2
		case 39:
			goto st2
		case 126:
			goto st2
		}
		switch {
		case data[p] < 48:
			switch {
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 46 {
					goto st2
				}
			case data[p] >= 42:
				goto st2
			}
		case data[p] > 57:
			switch {
			case data[p] > 90:
				if 95 <= data[p] && data[p] <= 122 {
					goto st2
				}
			case data[p] >= 65:
				goto st2
			}
		default:
			goto st2
		}
		goto st0
tr3:
//line msg_parse.rl:91

			msg.Method = string(data[mark:p])
		
	goto st3
	st3:
		if p++; p == pe {
			goto _test_eof3
		}
	st_case_3:
//line msg_parse.go:1297
		if data[p] == 32 {
			goto st0
		}
		goto tr5
tr5:
//line msg_parse.rl:55

			mark = p
		
	goto st4
	st4:
		if p++; p == pe {
			goto _test_eof4
		}
	st_case_4:
//line msg_parse.go:1313
		if data[p] == 32 {
			goto tr7
		}
		goto st4
tr7:
//line msg_parse.rl:103

			msg.Request, err = ParseURIBytes(data[mark:p])
			if err != nil { return nil, err }
		
	goto st5
	st5:
		if p++; p == pe {
			goto _test_eof5
		}
	st_case_5:
//line msg_parse.go:1330
		if data[p] == 83 {
			goto st6
		}
		goto st0
	st6:
		if p++; p == pe {
			goto _test_eof6
		}
	st_case_6:
		if data[p] == 73 {
			goto st7
		}
		goto st0
	st7:
		if p++; p == pe {
			goto _test_eof7
		}
	st_case_7:
		if data[p] == 80 {
			goto st8
		}
		goto st0
	st8:
		if p++; p == pe {
			goto _test_eof8
		}
	st_case_8:
		if data[p] == 47 {
			goto st9
		}
		goto st0
	st9:
		if p++; p == pe {
			goto _test_eof9
		}
	st_case_9:
		if 48 <= data[p] && data[p] <= 57 {
			goto tr12
		}
		goto st0
tr12:
//line msg_parse.rl:95

			msg.VersionMajor = msg.VersionMajor * 10 + (data[p] - 0x30)
		
	goto st10
	st10:
		if p++; p == pe {
			goto _test_eof10
		}
	st_case_10:
//line msg_parse.go:1382
		if data[p] == 46 {
			goto st11
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr12
		}
		goto st0
	st11:
		if p++; p == pe {
			goto _test_eof11
		}
	st_case_11:
		if 48 <= data[p] && data[p] <= 57 {
			goto tr14
		}
		goto st0
tr14:
//line msg_parse.rl:99

			msg.VersionMinor = msg.VersionMinor * 10 + (data[p] - 0x30)
		
	goto st12
	st12:
		if p++; p == pe {
			goto _test_eof12
		}
	st_case_12:
//line msg_parse.go:1410
		if data[p] == 13 {
			goto st13
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr14
		}
		goto st0
tr36:
//line msg_parse.rl:112

			msg.Phrase = string(buf[0:amt])
		
	goto st13
	st13:
		if p++; p == pe {
			goto _test_eof13
		}
	st_case_13:
//line msg_parse.go:1429
		if data[p] == 10 {
			goto tr16
		}
		goto st0
tr16:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
//line msg_parse.rl:116

			{goto st51 }
		
	goto st542
	st542:
		if p++; p == pe {
			goto _test_eof542
		}
	st_case_542:
//line msg_parse.go:1450
		goto st0
tr2:
//line msg_parse.rl:55

			mark = p
		
	goto st14
	st14:
		if p++; p == pe {
			goto _test_eof14
		}
	st_case_14:
//line msg_parse.go:1463
		switch data[p] {
		case 32:
			goto tr3
		case 33:
			goto st2
		case 37:
			goto st2
		case 39:
			goto st2
		case 73:
			goto st15
		case 126:
			goto st2
		}
		switch {
		case data[p] < 48:
			switch {
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 46 {
					goto st2
				}
			case data[p] >= 42:
				goto st2
			}
		case data[p] > 57:
			switch {
			case data[p] > 90:
				if 95 <= data[p] && data[p] <= 122 {
					goto st2
				}
			case data[p] >= 65:
				goto st2
			}
		default:
			goto st2
		}
		goto st0
	st15:
		if p++; p == pe {
			goto _test_eof15
		}
	st_case_15:
		switch data[p] {
		case 32:
			goto tr3
		case 33:
			goto st2
		case 37:
			goto st2
		case 39:
			goto st2
		case 80:
			goto st16
		case 126:
			goto st2
		}
		switch {
		case data[p] < 48:
			switch {
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 46 {
					goto st2
				}
			case data[p] >= 42:
				goto st2
			}
		case data[p] > 57:
			switch {
			case data[p] > 90:
				if 95 <= data[p] && data[p] <= 122 {
					goto st2
				}
			case data[p] >= 65:
				goto st2
			}
		default:
			goto st2
		}
		goto st0
	st16:
		if p++; p == pe {
			goto _test_eof16
		}
	st_case_16:
		switch data[p] {
		case 32:
			goto tr3
		case 33:
			goto st2
		case 37:
			goto st2
		case 39:
			goto st2
		case 47:
			goto st17
		case 126:
			goto st2
		}
		switch {
		case data[p] < 45:
			if 42 <= data[p] && data[p] <= 43 {
				goto st2
			}
		case data[p] > 57:
			switch {
			case data[p] > 90:
				if 95 <= data[p] && data[p] <= 122 {
					goto st2
				}
			case data[p] >= 65:
				goto st2
			}
		default:
			goto st2
		}
		goto st0
	st17:
		if p++; p == pe {
			goto _test_eof17
		}
	st_case_17:
		if 48 <= data[p] && data[p] <= 57 {
			goto tr20
		}
		goto st0
tr20:
//line msg_parse.rl:95

			msg.VersionMajor = msg.VersionMajor * 10 + (data[p] - 0x30)
		
	goto st18
	st18:
		if p++; p == pe {
			goto _test_eof18
		}
	st_case_18:
//line msg_parse.go:1600
		if data[p] == 46 {
			goto st19
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr20
		}
		goto st0
	st19:
		if p++; p == pe {
			goto _test_eof19
		}
	st_case_19:
		if 48 <= data[p] && data[p] <= 57 {
			goto tr22
		}
		goto st0
tr22:
//line msg_parse.rl:99

			msg.VersionMinor = msg.VersionMinor * 10 + (data[p] - 0x30)
		
	goto st20
	st20:
		if p++; p == pe {
			goto _test_eof20
		}
	st_case_20:
//line msg_parse.go:1628
		if data[p] == 32 {
			goto st21
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr22
		}
		goto st0
	st21:
		if p++; p == pe {
			goto _test_eof21
		}
	st_case_21:
		if 48 <= data[p] && data[p] <= 57 {
			goto tr24
		}
		goto st0
tr24:
//line msg_parse.rl:108

			msg.Status = msg.Status * 10 + (int(data[p]) - 0x30)
		
	goto st22
	st22:
		if p++; p == pe {
			goto _test_eof22
		}
	st_case_22:
//line msg_parse.go:1656
		if 48 <= data[p] && data[p] <= 57 {
			goto tr25
		}
		goto st0
tr25:
//line msg_parse.rl:108

			msg.Status = msg.Status * 10 + (int(data[p]) - 0x30)
		
	goto st23
	st23:
		if p++; p == pe {
			goto _test_eof23
		}
	st_case_23:
//line msg_parse.go:1672
		if 48 <= data[p] && data[p] <= 57 {
			goto tr26
		}
		goto st0
tr26:
//line msg_parse.rl:108

			msg.Status = msg.Status * 10 + (int(data[p]) - 0x30)
		
	goto st24
	st24:
		if p++; p == pe {
			goto _test_eof24
		}
	st_case_24:
//line msg_parse.go:1688
		if data[p] == 32 {
			goto st25
		}
		goto st0
	st25:
		if p++; p == pe {
			goto _test_eof25
		}
	st_case_25:
		switch data[p] {
		case 9:
			goto tr28
		case 37:
			goto tr29
		case 61:
			goto tr28
		case 95:
			goto tr28
		case 126:
			goto tr28
		}
		switch {
		case data[p] < 192:
			switch {
			case data[p] < 36:
				if 32 <= data[p] && data[p] <= 33 {
					goto tr28
				}
			case data[p] > 59:
				switch {
				case data[p] > 90:
					if 97 <= data[p] && data[p] <= 122 {
						goto tr28
					}
				case data[p] >= 63:
					goto tr28
				}
			default:
				goto tr28
			}
		case data[p] > 223:
			switch {
			case data[p] < 240:
				if 224 <= data[p] && data[p] <= 239 {
					goto tr31
				}
			case data[p] > 247:
				switch {
				case data[p] > 251:
					if 252 <= data[p] && data[p] <= 253 {
						goto tr34
					}
				case data[p] >= 248:
					goto tr33
				}
			default:
				goto tr32
			}
		default:
			goto tr30
		}
		goto st0
tr28:
//line msg_parse.rl:59

			amt = 0
		
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st26
tr35:
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st26
tr44:
//line msg_parse.rl:81

			hex += unhex(data[p])
			buf[amt] = hex
			amt++
		
	goto st26
	st26:
		if p++; p == pe {
			goto _test_eof26
		}
	st_case_26:
//line msg_parse.go:1782
		switch data[p] {
		case 9:
			goto tr35
		case 13:
			goto tr36
		case 37:
			goto st27
		case 61:
			goto tr35
		case 95:
			goto tr35
		case 126:
			goto tr35
		}
		switch {
		case data[p] < 192:
			switch {
			case data[p] < 36:
				if 32 <= data[p] && data[p] <= 33 {
					goto tr35
				}
			case data[p] > 59:
				switch {
				case data[p] > 90:
					if 97 <= data[p] && data[p] <= 122 {
						goto tr35
					}
				case data[p] >= 63:
					goto tr35
				}
			default:
				goto tr35
			}
		case data[p] > 223:
			switch {
			case data[p] < 240:
				if 224 <= data[p] && data[p] <= 239 {
					goto tr39
				}
			case data[p] > 247:
				switch {
				case data[p] > 251:
					if 252 <= data[p] && data[p] <= 253 {
						goto tr42
					}
				case data[p] >= 248:
					goto tr41
				}
			default:
				goto tr40
			}
		default:
			goto tr38
		}
		goto st0
tr29:
//line msg_parse.rl:59

			amt = 0
		
	goto st27
	st27:
		if p++; p == pe {
			goto _test_eof27
		}
	st_case_27:
//line msg_parse.go:1849
		switch {
		case data[p] < 65:
			if 48 <= data[p] && data[p] <= 57 {
				goto tr43
			}
		case data[p] > 70:
			if 97 <= data[p] && data[p] <= 102 {
				goto tr43
			}
		default:
			goto tr43
		}
		goto st0
tr43:
//line msg_parse.rl:77

			hex = unhex(data[p]) * 16
		
	goto st28
	st28:
		if p++; p == pe {
			goto _test_eof28
		}
	st_case_28:
//line msg_parse.go:1874
		switch {
		case data[p] < 65:
			if 48 <= data[p] && data[p] <= 57 {
				goto tr44
			}
		case data[p] > 70:
			if 97 <= data[p] && data[p] <= 102 {
				goto tr44
			}
		default:
			goto tr44
		}
		goto st0
tr30:
//line msg_parse.rl:59

			amt = 0
		
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st29
tr38:
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st29
	st29:
		if p++; p == pe {
			goto _test_eof29
		}
	st_case_29:
//line msg_parse.go:1911
		if 128 <= data[p] && data[p] <= 191 {
			goto tr35
		}
		goto st0
tr31:
//line msg_parse.rl:59

			amt = 0
		
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st30
tr39:
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st30
	st30:
		if p++; p == pe {
			goto _test_eof30
		}
	st_case_30:
//line msg_parse.go:1939
		if 128 <= data[p] && data[p] <= 191 {
			goto tr38
		}
		goto st0
tr32:
//line msg_parse.rl:59

			amt = 0
		
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st31
tr40:
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st31
	st31:
		if p++; p == pe {
			goto _test_eof31
		}
	st_case_31:
//line msg_parse.go:1967
		if 128 <= data[p] && data[p] <= 191 {
			goto tr39
		}
		goto st0
tr33:
//line msg_parse.rl:59

			amt = 0
		
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st32
tr41:
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st32
	st32:
		if p++; p == pe {
			goto _test_eof32
		}
	st_case_32:
//line msg_parse.go:1995
		if 128 <= data[p] && data[p] <= 191 {
			goto tr40
		}
		goto st0
tr34:
//line msg_parse.rl:59

			amt = 0
		
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st33
tr42:
//line msg_parse.rl:63

			buf[amt] = data[p]
			amt++
		
	goto st33
	st33:
		if p++; p == pe {
			goto _test_eof33
		}
	st_case_33:
//line msg_parse.go:2023
		if 128 <= data[p] && data[p] <= 191 {
			goto tr41
		}
		goto st0
	st34:
		if p++; p == pe {
			goto _test_eof34
		}
	st_case_34:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto tr45
		case 269:
			goto tr51
		case 525:
			goto tr52
		}
		switch {
		case _widec < 224:
			switch {
			case _widec > 127:
				if 192 <= _widec && _widec <= 223 {
					goto tr46
				}
			case _widec >= 32:
				goto tr45
			}
		case _widec > 239:
			switch {
			case _widec < 248:
				if 240 <= _widec && _widec <= 247 {
					goto tr48
				}
			case _widec > 251:
				if 252 <= _widec && _widec <= 253 {
					goto tr50
				}
			default:
				goto tr49
			}
		default:
			goto tr47
		}
		goto st0
tr45:
//line msg_parse.rl:55

			mark = p
		
	goto st35
	st35:
		if p++; p == pe {
			goto _test_eof35
		}
	st_case_35:
//line msg_parse.go:2086
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st35
		case 269:
			goto st41
		case 525:
			goto st42
		}
		switch {
		case _widec < 224:
			switch {
			case _widec > 127:
				if 192 <= _widec && _widec <= 223 {
					goto st36
				}
			case _widec >= 32:
				goto st35
			}
		case _widec > 239:
			switch {
			case _widec < 248:
				if 240 <= _widec && _widec <= 247 {
					goto st38
				}
			case _widec > 251:
				if 252 <= _widec && _widec <= 253 {
					goto st40
				}
			default:
				goto st39
			}
		default:
			goto st37
		}
		goto st0
tr46:
//line msg_parse.rl:55

			mark = p
		
	goto st36
	st36:
		if p++; p == pe {
			goto _test_eof36
		}
	st_case_36:
//line msg_parse.go:2140
		if 128 <= data[p] && data[p] <= 191 {
			goto st35
		}
		goto st0
tr47:
//line msg_parse.rl:55

			mark = p
		
	goto st37
	st37:
		if p++; p == pe {
			goto _test_eof37
		}
	st_case_37:
//line msg_parse.go:2156
		if 128 <= data[p] && data[p] <= 191 {
			goto st36
		}
		goto st0
tr48:
//line msg_parse.rl:55

			mark = p
		
	goto st38
	st38:
		if p++; p == pe {
			goto _test_eof38
		}
	st_case_38:
//line msg_parse.go:2172
		if 128 <= data[p] && data[p] <= 191 {
			goto st37
		}
		goto st0
tr49:
//line msg_parse.rl:55

			mark = p
		
	goto st39
	st39:
		if p++; p == pe {
			goto _test_eof39
		}
	st_case_39:
//line msg_parse.go:2188
		if 128 <= data[p] && data[p] <= 191 {
			goto st38
		}
		goto st0
tr50:
//line msg_parse.rl:55

			mark = p
		
	goto st40
	st40:
		if p++; p == pe {
			goto _test_eof40
		}
	st_case_40:
//line msg_parse.go:2204
		if 128 <= data[p] && data[p] <= 191 {
			goto st39
		}
		goto st0
tr51:
//line msg_parse.rl:55

			mark = p
		
	goto st41
	st41:
		if p++; p == pe {
			goto _test_eof41
		}
	st_case_41:
//line msg_parse.go:2220
		if data[p] == 10 {
			goto tr61
		}
		goto st0
tr61:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
//line msg_parse.rl:140
{
			b := data[mark:p - 1]
			if value != nil {
				*value = string(b)
			} else if addr != nil {
				*addr, err = ParseAddrBytes(b, *addr)
				if err != nil { return nil, err }
			} else {
				if msg.Headers == nil {
					msg.Headers = Headers{}
				}
				msg.Headers[name] = string(b)
			}
		}
//line msg_parse.rl:116

			{goto st51 }
		
	goto st543
	st543:
		if p++; p == pe {
			goto _test_eof543
		}
	st_case_543:
//line msg_parse.go:2256
		goto st0
tr52:
//line msg_parse.rl:55

			mark = p
		
	goto st42
	st42:
		if p++; p == pe {
			goto _test_eof42
		}
	st_case_42:
//line msg_parse.go:2269
		if data[p] == 10 {
			goto tr62
		}
		goto st0
tr62:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st43
	st43:
		if p++; p == pe {
			goto _test_eof43
		}
	st_case_43:
//line msg_parse.go:2286
		switch data[p] {
		case 9:
			goto st35
		case 32:
			goto st35
		}
		goto st0
	st44:
		if p++; p == pe {
			goto _test_eof44
		}
	st_case_44:
		switch data[p] {
		case 33:
			goto tr63
		case 37:
			goto tr63
		case 39:
			goto tr63
		case 126:
			goto tr63
		}
		switch {
		case data[p] < 48:
			switch {
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 46 {
					goto tr63
				}
			case data[p] >= 42:
				goto tr63
			}
		case data[p] > 57:
			switch {
			case data[p] > 90:
				if 95 <= data[p] && data[p] <= 122 {
					goto tr63
				}
			case data[p] >= 65:
				goto tr63
			}
		default:
			goto tr63
		}
		goto st0
tr63:
//line msg_parse.rl:55

			mark = p
		
	goto st45
	st45:
		if p++; p == pe {
			goto _test_eof45
		}
	st_case_45:
//line msg_parse.go:2343
		switch data[p] {
		case 9:
			goto tr64
		case 32:
			goto tr64
		case 33:
			goto st45
		case 37:
			goto st45
		case 39:
			goto st45
		case 58:
			goto tr66
		case 126:
			goto st45
		}
		switch {
		case data[p] < 48:
			switch {
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 46 {
					goto st45
				}
			case data[p] >= 42:
				goto st45
			}
		case data[p] > 57:
			switch {
			case data[p] > 90:
				if 95 <= data[p] && data[p] <= 122 {
					goto st45
				}
			case data[p] >= 65:
				goto st45
			}
		default:
			goto st45
		}
		goto st0
tr64:
//line msg_parse.rl:136

			name = string(data[mark:p])
		
	goto st46
	st46:
		if p++; p == pe {
			goto _test_eof46
		}
	st_case_46:
//line msg_parse.go:2394
		switch data[p] {
		case 9:
			goto st46
		case 32:
			goto st46
		case 58:
			goto st47
		}
		goto st0
tr66:
//line msg_parse.rl:136

			name = string(data[mark:p])
		
	goto st47
	st47:
		if p++; p == pe {
			goto _test_eof47
		}
	st_case_47:
//line msg_parse.go:2415
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st47
		case 32:
			goto st47
		case 269:
			goto tr69
		case 525:
			goto st48
		}
		switch {
		case _widec > 12:
			if 14 <= _widec {
				goto tr69
			}
		default:
			goto tr69
		}
		goto st0
tr69:
//line msg_parse.rl:351
value=nil;addr=nil
//line msg_parse.rl:120

			p--

			{goto st34 }
		
	goto st544
	st544:
		if p++; p == pe {
			goto _test_eof544
		}
	st_case_544:
//line msg_parse.go:2457
		goto st0
	st48:
		if p++; p == pe {
			goto _test_eof48
		}
	st_case_48:
		if data[p] == 10 {
			goto tr71
		}
		goto st0
tr71:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st49
	st49:
		if p++; p == pe {
			goto _test_eof49
		}
	st_case_49:
//line msg_parse.go:2480
		switch data[p] {
		case 9:
			goto st50
		case 32:
			goto st50
		}
		goto st0
	st50:
		if p++; p == pe {
			goto _test_eof50
		}
	st_case_50:
		switch data[p] {
		case 9:
			goto st50
		case 32:
			goto st50
		}
		goto tr69
	st51:
		if p++; p == pe {
			goto _test_eof51
		}
	st_case_51:
		switch data[p] {
		case 13:
			goto st52
		case 65:
			goto tr75
		case 66:
			goto tr76
		case 67:
			goto tr77
		case 68:
			goto tr78
		case 69:
			goto tr79
		case 70:
			goto tr80
		case 73:
			goto tr81
		case 75:
			goto tr82
		case 76:
			goto st279
		case 77:
			goto tr84
		case 79:
			goto tr85
		case 80:
			goto tr86
		case 82:
			goto tr87
		case 83:
			goto tr88
		case 84:
			goto tr89
		case 85:
			goto tr90
		case 86:
			goto st505
		case 87:
			goto tr92
		case 97:
			goto tr75
		case 98:
			goto tr76
		case 99:
			goto tr77
		case 100:
			goto tr78
		case 101:
			goto tr79
		case 102:
			goto tr80
		case 105:
			goto tr81
		case 107:
			goto tr82
		case 108:
			goto st279
		case 109:
			goto tr84
		case 111:
			goto tr85
		case 112:
			goto tr86
		case 114:
			goto tr87
		case 115:
			goto tr88
		case 116:
			goto tr89
		case 117:
			goto tr90
		case 118:
			goto st505
		case 119:
			goto tr92
		}
		goto tr73
	st52:
		if p++; p == pe {
			goto _test_eof52
		}
	st_case_52:
		if data[p] == 10 {
			goto tr93
		}
		goto st0
tr217:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
//line msg_parse.rl:116

			{goto st51 }
		
	goto st545
tr93:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
//line msg_parse.rl:46

			{p++; cs = 545; goto _out }
		
	goto st545
tr101:
//line msg_parse.rl:355
addr=nil
//line msg_parse.rl:120

			p--

			{goto st34 }
		
	goto st545
tr251:
//line msg_parse.rl:354
value=nil
//line msg_parse.rl:120

			p--

			{goto st34 }
		
	goto st545
	st545:
		if p++; p == pe {
			goto _test_eof545
		}
	st_case_545:
//line msg_parse.go:2638
		goto st0
tr75:
//line msg_parse.rl:55

			mark = p
		
	goto st53
	st53:
		if p++; p == pe {
			goto _test_eof53
		}
	st_case_53:
//line msg_parse.go:2651
		switch data[p] {
		case 9:
			goto tr94
		case 32:
			goto tr94
		case 58:
			goto tr95
		case 67:
			goto st59
		case 76:
			goto st88
		case 85:
			goto st107
		case 99:
			goto st59
		case 108:
			goto st88
		case 117:
			goto st107
		}
		goto st0
tr94:
//line msg_parse.rl:302
value=&msg.AcceptContact
	goto st54
tr110:
//line msg_parse.rl:301
value=&msg.Accept
	goto st54
tr129:
//line msg_parse.rl:303
value=&msg.AcceptEncoding
	goto st54
tr138:
//line msg_parse.rl:304
value=&msg.AcceptLanguage
	goto st54
tr149:
//line msg_parse.rl:307
value=&msg.AlertInfo
	goto st54
tr153:
//line msg_parse.rl:305
value=&msg.Allow
	goto st54
tr162:
//line msg_parse.rl:306
value=&msg.AllowEvents
	goto st54
tr182:
//line msg_parse.rl:308
value=&msg.AuthenticationInfo
	goto st54
tr192:
//line msg_parse.rl:309
value=&msg.Authorization
	goto st54
tr194:
//line msg_parse.rl:326
value=&msg.ReferredBy
	goto st54
tr239:
//line msg_parse.rl:313
value=&msg.CallInfo
	goto st54
tr272:
//line msg_parse.rl:310
value=&msg.ContentDisposition
	goto st54
tr281:
//line msg_parse.rl:312
value=&msg.ContentEncoding
	goto st54
tr291:
//line msg_parse.rl:311
value=&msg.ContentLanguage
	goto st54
tr324:
//line msg_parse.rl:314
value=&msg.Date
	goto st54
tr337:
//line msg_parse.rl:315
value=&msg.ErrorInfo
	goto st54
tr342:
//line msg_parse.rl:316
value=&msg.Event
	goto st54
tr370:
//line msg_parse.rl:317
value=&msg.InReplyTo
	goto st54
tr372:
//line msg_parse.rl:331
value=&msg.Supported
	goto st54
tr409:
//line msg_parse.rl:319
value=&msg.MIMEVersion
	goto st54
tr436:
//line msg_parse.rl:320
value=&msg.Organization
	goto st54
tr466:
//line msg_parse.rl:321
value=&msg.Priority
	goto st54
tr485:
//line msg_parse.rl:322
value=&msg.ProxyAuthenticate
	goto st54
tr495:
//line msg_parse.rl:323
value=&msg.ProxyAuthorization
	goto st54
tr503:
//line msg_parse.rl:324
value=&msg.ProxyRequire
	goto st54
tr505:
//line msg_parse.rl:325
value=&msg.ReferTo
	goto st54
tr556:
//line msg_parse.rl:318
value=&msg.ReplyTo
	goto st54
tr562:
//line msg_parse.rl:327
value=&msg.Require
	goto st54
tr572:
//line msg_parse.rl:328
value=&msg.RetryAfter
	goto st54
tr579:
//line msg_parse.rl:330
value=&msg.Subject
	goto st54
tr587:
//line msg_parse.rl:329
value=&msg.Server
	goto st54
tr612:
//line msg_parse.rl:332
value=&msg.Timestamp
	goto st54
tr614:
//line msg_parse.rl:305
value=&msg.Allow
//line msg_parse.rl:306
value=&msg.AllowEvents
	goto st54
tr627:
//line msg_parse.rl:333
value=&msg.Unsupported
	goto st54
tr637:
//line msg_parse.rl:334
value=&msg.UserAgent
	goto st54
tr669:
//line msg_parse.rl:335
value=&msg.Warning
	goto st54
tr685:
//line msg_parse.rl:336
value=&msg.WWWAuthenticate
	goto st54
	st54:
		if p++; p == pe {
			goto _test_eof54
		}
	st_case_54:
//line msg_parse.go:2828
		switch data[p] {
		case 9:
			goto st54
		case 32:
			goto st54
		case 58:
			goto st55
		}
		goto st0
tr95:
//line msg_parse.rl:302
value=&msg.AcceptContact
	goto st55
tr112:
//line msg_parse.rl:301
value=&msg.Accept
	goto st55
tr130:
//line msg_parse.rl:303
value=&msg.AcceptEncoding
	goto st55
tr139:
//line msg_parse.rl:304
value=&msg.AcceptLanguage
	goto st55
tr150:
//line msg_parse.rl:307
value=&msg.AlertInfo
	goto st55
tr155:
//line msg_parse.rl:305
value=&msg.Allow
	goto st55
tr163:
//line msg_parse.rl:306
value=&msg.AllowEvents
	goto st55
tr183:
//line msg_parse.rl:308
value=&msg.AuthenticationInfo
	goto st55
tr193:
//line msg_parse.rl:309
value=&msg.Authorization
	goto st55
tr195:
//line msg_parse.rl:326
value=&msg.ReferredBy
	goto st55
tr240:
//line msg_parse.rl:313
value=&msg.CallInfo
	goto st55
tr273:
//line msg_parse.rl:310
value=&msg.ContentDisposition
	goto st55
tr282:
//line msg_parse.rl:312
value=&msg.ContentEncoding
	goto st55
tr292:
//line msg_parse.rl:311
value=&msg.ContentLanguage
	goto st55
tr325:
//line msg_parse.rl:314
value=&msg.Date
	goto st55
tr338:
//line msg_parse.rl:315
value=&msg.ErrorInfo
	goto st55
tr343:
//line msg_parse.rl:316
value=&msg.Event
	goto st55
tr371:
//line msg_parse.rl:317
value=&msg.InReplyTo
	goto st55
tr373:
//line msg_parse.rl:331
value=&msg.Supported
	goto st55
tr410:
//line msg_parse.rl:319
value=&msg.MIMEVersion
	goto st55
tr437:
//line msg_parse.rl:320
value=&msg.Organization
	goto st55
tr467:
//line msg_parse.rl:321
value=&msg.Priority
	goto st55
tr486:
//line msg_parse.rl:322
value=&msg.ProxyAuthenticate
	goto st55
tr496:
//line msg_parse.rl:323
value=&msg.ProxyAuthorization
	goto st55
tr504:
//line msg_parse.rl:324
value=&msg.ProxyRequire
	goto st55
tr506:
//line msg_parse.rl:325
value=&msg.ReferTo
	goto st55
tr557:
//line msg_parse.rl:318
value=&msg.ReplyTo
	goto st55
tr563:
//line msg_parse.rl:327
value=&msg.Require
	goto st55
tr573:
//line msg_parse.rl:328
value=&msg.RetryAfter
	goto st55
tr580:
//line msg_parse.rl:330
value=&msg.Subject
	goto st55
tr588:
//line msg_parse.rl:329
value=&msg.Server
	goto st55
tr613:
//line msg_parse.rl:332
value=&msg.Timestamp
	goto st55
tr615:
//line msg_parse.rl:305
value=&msg.Allow
//line msg_parse.rl:306
value=&msg.AllowEvents
	goto st55
tr628:
//line msg_parse.rl:333
value=&msg.Unsupported
	goto st55
tr638:
//line msg_parse.rl:334
value=&msg.UserAgent
	goto st55
tr670:
//line msg_parse.rl:335
value=&msg.Warning
	goto st55
tr686:
//line msg_parse.rl:336
value=&msg.WWWAuthenticate
	goto st55
	st55:
		if p++; p == pe {
			goto _test_eof55
		}
	st_case_55:
//line msg_parse.go:2993
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st55
		case 32:
			goto st55
		case 269:
			goto tr101
		case 525:
			goto st56
		}
		switch {
		case _widec > 12:
			if 14 <= _widec {
				goto tr101
			}
		default:
			goto tr101
		}
		goto st0
	st56:
		if p++; p == pe {
			goto _test_eof56
		}
	st_case_56:
		if data[p] == 10 {
			goto tr103
		}
		goto st0
tr103:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st57
	st57:
		if p++; p == pe {
			goto _test_eof57
		}
	st_case_57:
//line msg_parse.go:3041
		switch data[p] {
		case 9:
			goto st58
		case 32:
			goto st58
		}
		goto st0
	st58:
		if p++; p == pe {
			goto _test_eof58
		}
	st_case_58:
		switch data[p] {
		case 9:
			goto st58
		case 32:
			goto st58
		}
		goto tr101
	st59:
		if p++; p == pe {
			goto _test_eof59
		}
	st_case_59:
		switch data[p] {
		case 67:
			goto st60
		case 99:
			goto st60
		}
		goto tr105
	st60:
		if p++; p == pe {
			goto _test_eof60
		}
	st_case_60:
		switch data[p] {
		case 69:
			goto st61
		case 101:
			goto st61
		}
		goto tr105
	st61:
		if p++; p == pe {
			goto _test_eof61
		}
	st_case_61:
		switch data[p] {
		case 80:
			goto st62
		case 112:
			goto st62
		}
		goto tr105
	st62:
		if p++; p == pe {
			goto _test_eof62
		}
	st_case_62:
		switch data[p] {
		case 84:
			goto st63
		case 116:
			goto st63
		}
		goto tr105
	st63:
		if p++; p == pe {
			goto _test_eof63
		}
	st_case_63:
		switch data[p] {
		case 9:
			goto tr110
		case 32:
			goto tr110
		case 45:
			goto st64
		case 58:
			goto tr112
		}
		goto st0
	st64:
		if p++; p == pe {
			goto _test_eof64
		}
	st_case_64:
		switch data[p] {
		case 67:
			goto st65
		case 69:
			goto st72
		case 76:
			goto st80
		case 99:
			goto st65
		case 101:
			goto st72
		case 108:
			goto st80
		}
		goto tr105
	st65:
		if p++; p == pe {
			goto _test_eof65
		}
	st_case_65:
		switch data[p] {
		case 79:
			goto st66
		case 111:
			goto st66
		}
		goto tr105
	st66:
		if p++; p == pe {
			goto _test_eof66
		}
	st_case_66:
		switch data[p] {
		case 78:
			goto st67
		case 110:
			goto st67
		}
		goto tr105
	st67:
		if p++; p == pe {
			goto _test_eof67
		}
	st_case_67:
		switch data[p] {
		case 84:
			goto st68
		case 116:
			goto st68
		}
		goto tr105
	st68:
		if p++; p == pe {
			goto _test_eof68
		}
	st_case_68:
		switch data[p] {
		case 65:
			goto st69
		case 97:
			goto st69
		}
		goto tr105
	st69:
		if p++; p == pe {
			goto _test_eof69
		}
	st_case_69:
		switch data[p] {
		case 67:
			goto st70
		case 99:
			goto st70
		}
		goto tr105
	st70:
		if p++; p == pe {
			goto _test_eof70
		}
	st_case_70:
		switch data[p] {
		case 84:
			goto st71
		case 116:
			goto st71
		}
		goto tr105
	st71:
		if p++; p == pe {
			goto _test_eof71
		}
	st_case_71:
		switch data[p] {
		case 9:
			goto tr94
		case 32:
			goto tr94
		case 58:
			goto tr95
		}
		goto st0
	st72:
		if p++; p == pe {
			goto _test_eof72
		}
	st_case_72:
		switch data[p] {
		case 78:
			goto st73
		case 110:
			goto st73
		}
		goto tr105
	st73:
		if p++; p == pe {
			goto _test_eof73
		}
	st_case_73:
		switch data[p] {
		case 67:
			goto st74
		case 99:
			goto st74
		}
		goto tr105
	st74:
		if p++; p == pe {
			goto _test_eof74
		}
	st_case_74:
		switch data[p] {
		case 79:
			goto st75
		case 111:
			goto st75
		}
		goto tr105
	st75:
		if p++; p == pe {
			goto _test_eof75
		}
	st_case_75:
		switch data[p] {
		case 68:
			goto st76
		case 100:
			goto st76
		}
		goto tr105
	st76:
		if p++; p == pe {
			goto _test_eof76
		}
	st_case_76:
		switch data[p] {
		case 73:
			goto st77
		case 105:
			goto st77
		}
		goto tr105
	st77:
		if p++; p == pe {
			goto _test_eof77
		}
	st_case_77:
		switch data[p] {
		case 78:
			goto st78
		case 110:
			goto st78
		}
		goto tr105
	st78:
		if p++; p == pe {
			goto _test_eof78
		}
	st_case_78:
		switch data[p] {
		case 71:
			goto st79
		case 103:
			goto st79
		}
		goto tr105
	st79:
		if p++; p == pe {
			goto _test_eof79
		}
	st_case_79:
		switch data[p] {
		case 9:
			goto tr129
		case 32:
			goto tr129
		case 58:
			goto tr130
		}
		goto st0
	st80:
		if p++; p == pe {
			goto _test_eof80
		}
	st_case_80:
		switch data[p] {
		case 65:
			goto st81
		case 97:
			goto st81
		}
		goto tr105
	st81:
		if p++; p == pe {
			goto _test_eof81
		}
	st_case_81:
		switch data[p] {
		case 78:
			goto st82
		case 110:
			goto st82
		}
		goto tr105
	st82:
		if p++; p == pe {
			goto _test_eof82
		}
	st_case_82:
		switch data[p] {
		case 71:
			goto st83
		case 103:
			goto st83
		}
		goto tr105
	st83:
		if p++; p == pe {
			goto _test_eof83
		}
	st_case_83:
		switch data[p] {
		case 85:
			goto st84
		case 117:
			goto st84
		}
		goto tr105
	st84:
		if p++; p == pe {
			goto _test_eof84
		}
	st_case_84:
		switch data[p] {
		case 65:
			goto st85
		case 97:
			goto st85
		}
		goto tr105
	st85:
		if p++; p == pe {
			goto _test_eof85
		}
	st_case_85:
		switch data[p] {
		case 71:
			goto st86
		case 103:
			goto st86
		}
		goto tr105
	st86:
		if p++; p == pe {
			goto _test_eof86
		}
	st_case_86:
		switch data[p] {
		case 69:
			goto st87
		case 101:
			goto st87
		}
		goto tr105
	st87:
		if p++; p == pe {
			goto _test_eof87
		}
	st_case_87:
		switch data[p] {
		case 9:
			goto tr138
		case 32:
			goto tr138
		case 58:
			goto tr139
		}
		goto st0
	st88:
		if p++; p == pe {
			goto _test_eof88
		}
	st_case_88:
		switch data[p] {
		case 69:
			goto st89
		case 76:
			goto st97
		case 101:
			goto st89
		case 108:
			goto st97
		}
		goto tr105
	st89:
		if p++; p == pe {
			goto _test_eof89
		}
	st_case_89:
		switch data[p] {
		case 82:
			goto st90
		case 114:
			goto st90
		}
		goto tr105
	st90:
		if p++; p == pe {
			goto _test_eof90
		}
	st_case_90:
		switch data[p] {
		case 84:
			goto st91
		case 116:
			goto st91
		}
		goto tr105
	st91:
		if p++; p == pe {
			goto _test_eof91
		}
	st_case_91:
		if data[p] == 45 {
			goto st92
		}
		goto tr105
	st92:
		if p++; p == pe {
			goto _test_eof92
		}
	st_case_92:
		switch data[p] {
		case 73:
			goto st93
		case 105:
			goto st93
		}
		goto tr105
	st93:
		if p++; p == pe {
			goto _test_eof93
		}
	st_case_93:
		switch data[p] {
		case 78:
			goto st94
		case 110:
			goto st94
		}
		goto tr105
	st94:
		if p++; p == pe {
			goto _test_eof94
		}
	st_case_94:
		switch data[p] {
		case 70:
			goto st95
		case 102:
			goto st95
		}
		goto tr105
	st95:
		if p++; p == pe {
			goto _test_eof95
		}
	st_case_95:
		switch data[p] {
		case 79:
			goto st96
		case 111:
			goto st96
		}
		goto tr105
	st96:
		if p++; p == pe {
			goto _test_eof96
		}
	st_case_96:
		switch data[p] {
		case 9:
			goto tr149
		case 32:
			goto tr149
		case 58:
			goto tr150
		}
		goto st0
	st97:
		if p++; p == pe {
			goto _test_eof97
		}
	st_case_97:
		switch data[p] {
		case 79:
			goto st98
		case 111:
			goto st98
		}
		goto tr105
	st98:
		if p++; p == pe {
			goto _test_eof98
		}
	st_case_98:
		switch data[p] {
		case 87:
			goto st99
		case 119:
			goto st99
		}
		goto tr105
	st99:
		if p++; p == pe {
			goto _test_eof99
		}
	st_case_99:
		switch data[p] {
		case 9:
			goto tr153
		case 32:
			goto tr153
		case 45:
			goto st100
		case 58:
			goto tr155
		}
		goto st0
	st100:
		if p++; p == pe {
			goto _test_eof100
		}
	st_case_100:
		switch data[p] {
		case 69:
			goto st101
		case 101:
			goto st101
		}
		goto tr105
	st101:
		if p++; p == pe {
			goto _test_eof101
		}
	st_case_101:
		switch data[p] {
		case 86:
			goto st102
		case 118:
			goto st102
		}
		goto tr105
	st102:
		if p++; p == pe {
			goto _test_eof102
		}
	st_case_102:
		switch data[p] {
		case 69:
			goto st103
		case 101:
			goto st103
		}
		goto tr105
	st103:
		if p++; p == pe {
			goto _test_eof103
		}
	st_case_103:
		switch data[p] {
		case 78:
			goto st104
		case 110:
			goto st104
		}
		goto tr105
	st104:
		if p++; p == pe {
			goto _test_eof104
		}
	st_case_104:
		switch data[p] {
		case 84:
			goto st105
		case 116:
			goto st105
		}
		goto tr105
	st105:
		if p++; p == pe {
			goto _test_eof105
		}
	st_case_105:
		switch data[p] {
		case 83:
			goto st106
		case 115:
			goto st106
		}
		goto tr105
	st106:
		if p++; p == pe {
			goto _test_eof106
		}
	st_case_106:
		switch data[p] {
		case 9:
			goto tr162
		case 32:
			goto tr162
		case 58:
			goto tr163
		}
		goto st0
	st107:
		if p++; p == pe {
			goto _test_eof107
		}
	st_case_107:
		switch data[p] {
		case 84:
			goto st108
		case 116:
			goto st108
		}
		goto tr105
	st108:
		if p++; p == pe {
			goto _test_eof108
		}
	st_case_108:
		switch data[p] {
		case 72:
			goto st109
		case 104:
			goto st109
		}
		goto tr105
	st109:
		if p++; p == pe {
			goto _test_eof109
		}
	st_case_109:
		switch data[p] {
		case 69:
			goto st110
		case 79:
			goto st125
		case 101:
			goto st110
		case 111:
			goto st125
		}
		goto tr105
	st110:
		if p++; p == pe {
			goto _test_eof110
		}
	st_case_110:
		switch data[p] {
		case 78:
			goto st111
		case 110:
			goto st111
		}
		goto tr105
	st111:
		if p++; p == pe {
			goto _test_eof111
		}
	st_case_111:
		switch data[p] {
		case 84:
			goto st112
		case 116:
			goto st112
		}
		goto tr105
	st112:
		if p++; p == pe {
			goto _test_eof112
		}
	st_case_112:
		switch data[p] {
		case 73:
			goto st113
		case 105:
			goto st113
		}
		goto tr105
	st113:
		if p++; p == pe {
			goto _test_eof113
		}
	st_case_113:
		switch data[p] {
		case 67:
			goto st114
		case 99:
			goto st114
		}
		goto tr105
	st114:
		if p++; p == pe {
			goto _test_eof114
		}
	st_case_114:
		switch data[p] {
		case 65:
			goto st115
		case 97:
			goto st115
		}
		goto tr105
	st115:
		if p++; p == pe {
			goto _test_eof115
		}
	st_case_115:
		switch data[p] {
		case 84:
			goto st116
		case 116:
			goto st116
		}
		goto tr105
	st116:
		if p++; p == pe {
			goto _test_eof116
		}
	st_case_116:
		switch data[p] {
		case 73:
			goto st117
		case 105:
			goto st117
		}
		goto tr105
	st117:
		if p++; p == pe {
			goto _test_eof117
		}
	st_case_117:
		switch data[p] {
		case 79:
			goto st118
		case 111:
			goto st118
		}
		goto tr105
	st118:
		if p++; p == pe {
			goto _test_eof118
		}
	st_case_118:
		switch data[p] {
		case 78:
			goto st119
		case 110:
			goto st119
		}
		goto tr105
	st119:
		if p++; p == pe {
			goto _test_eof119
		}
	st_case_119:
		if data[p] == 45 {
			goto st120
		}
		goto tr105
	st120:
		if p++; p == pe {
			goto _test_eof120
		}
	st_case_120:
		switch data[p] {
		case 73:
			goto st121
		case 105:
			goto st121
		}
		goto tr105
	st121:
		if p++; p == pe {
			goto _test_eof121
		}
	st_case_121:
		switch data[p] {
		case 78:
			goto st122
		case 110:
			goto st122
		}
		goto tr105
	st122:
		if p++; p == pe {
			goto _test_eof122
		}
	st_case_122:
		switch data[p] {
		case 70:
			goto st123
		case 102:
			goto st123
		}
		goto tr105
	st123:
		if p++; p == pe {
			goto _test_eof123
		}
	st_case_123:
		switch data[p] {
		case 79:
			goto st124
		case 111:
			goto st124
		}
		goto tr105
	st124:
		if p++; p == pe {
			goto _test_eof124
		}
	st_case_124:
		switch data[p] {
		case 9:
			goto tr182
		case 32:
			goto tr182
		case 58:
			goto tr183
		}
		goto st0
	st125:
		if p++; p == pe {
			goto _test_eof125
		}
	st_case_125:
		switch data[p] {
		case 82:
			goto st126
		case 114:
			goto st126
		}
		goto tr105
	st126:
		if p++; p == pe {
			goto _test_eof126
		}
	st_case_126:
		switch data[p] {
		case 73:
			goto st127
		case 105:
			goto st127
		}
		goto tr105
	st127:
		if p++; p == pe {
			goto _test_eof127
		}
	st_case_127:
		switch data[p] {
		case 90:
			goto st128
		case 122:
			goto st128
		}
		goto tr105
	st128:
		if p++; p == pe {
			goto _test_eof128
		}
	st_case_128:
		switch data[p] {
		case 65:
			goto st129
		case 97:
			goto st129
		}
		goto tr105
	st129:
		if p++; p == pe {
			goto _test_eof129
		}
	st_case_129:
		switch data[p] {
		case 84:
			goto st130
		case 116:
			goto st130
		}
		goto tr105
	st130:
		if p++; p == pe {
			goto _test_eof130
		}
	st_case_130:
		switch data[p] {
		case 73:
			goto st131
		case 105:
			goto st131
		}
		goto tr105
	st131:
		if p++; p == pe {
			goto _test_eof131
		}
	st_case_131:
		switch data[p] {
		case 79:
			goto st132
		case 111:
			goto st132
		}
		goto tr105
	st132:
		if p++; p == pe {
			goto _test_eof132
		}
	st_case_132:
		switch data[p] {
		case 78:
			goto st133
		case 110:
			goto st133
		}
		goto tr105
	st133:
		if p++; p == pe {
			goto _test_eof133
		}
	st_case_133:
		switch data[p] {
		case 9:
			goto tr192
		case 32:
			goto tr192
		case 58:
			goto tr193
		}
		goto st0
tr76:
//line msg_parse.rl:55

			mark = p
		
	goto st134
	st134:
		if p++; p == pe {
			goto _test_eof134
		}
	st_case_134:
//line msg_parse.go:4004
		switch data[p] {
		case 9:
			goto tr194
		case 32:
			goto tr194
		case 58:
			goto tr195
		}
		goto st0
tr77:
//line msg_parse.rl:55

			mark = p
		
	goto st135
	st135:
		if p++; p == pe {
			goto _test_eof135
		}
	st_case_135:
//line msg_parse.go:4025
		switch data[p] {
		case 9:
			goto st136
		case 32:
			goto st136
		case 58:
			goto st137
		case 65:
			goto st150
		case 79:
			goto st166
		case 83:
			goto st221
		case 97:
			goto st150
		case 111:
			goto st166
		case 115:
			goto st221
		}
		goto tr73
	st136:
		if p++; p == pe {
			goto _test_eof136
		}
	st_case_136:
		switch data[p] {
		case 9:
			goto st136
		case 32:
			goto st136
		case 58:
			goto st137
		}
		goto st0
	st137:
		if p++; p == pe {
			goto _test_eof137
		}
	st_case_137:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st137
		case 32:
			goto st137
		case 269:
			goto tr207
		case 525:
			goto st147
		}
		switch {
		case _widec < 224:
			switch {
			case _widec > 127:
				if 192 <= _widec && _widec <= 223 {
					goto tr202
				}
			case _widec >= 33:
				goto tr201
			}
		case _widec > 239:
			switch {
			case _widec < 248:
				if 240 <= _widec && _widec <= 247 {
					goto tr204
				}
			case _widec > 251:
				if 252 <= _widec && _widec <= 253 {
					goto tr206
				}
			default:
				goto tr205
			}
		default:
			goto tr203
		}
		goto st0
tr201:
//line msg_parse.rl:55

			mark = p
		
	goto st138
	st138:
		if p++; p == pe {
			goto _test_eof138
		}
	st_case_138:
//line msg_parse.go:4121
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st138
		case 269:
			goto tr215
		case 525:
			goto st145
		}
		switch {
		case _widec < 224:
			switch {
			case _widec > 127:
				if 192 <= _widec && _widec <= 223 {
					goto st139
				}
			case _widec >= 32:
				goto st138
			}
		case _widec > 239:
			switch {
			case _widec < 248:
				if 240 <= _widec && _widec <= 247 {
					goto st141
				}
			case _widec > 251:
				if 252 <= _widec && _widec <= 253 {
					goto st143
				}
			default:
				goto st142
			}
		default:
			goto st140
		}
		goto st0
tr202:
//line msg_parse.rl:55

			mark = p
		
	goto st139
	st139:
		if p++; p == pe {
			goto _test_eof139
		}
	st_case_139:
//line msg_parse.go:4175
		if 128 <= data[p] && data[p] <= 191 {
			goto st138
		}
		goto st0
tr203:
//line msg_parse.rl:55

			mark = p
		
	goto st140
	st140:
		if p++; p == pe {
			goto _test_eof140
		}
	st_case_140:
//line msg_parse.go:4191
		if 128 <= data[p] && data[p] <= 191 {
			goto st139
		}
		goto st0
tr204:
//line msg_parse.rl:55

			mark = p
		
	goto st141
	st141:
		if p++; p == pe {
			goto _test_eof141
		}
	st_case_141:
//line msg_parse.go:4207
		if 128 <= data[p] && data[p] <= 191 {
			goto st140
		}
		goto st0
tr205:
//line msg_parse.rl:55

			mark = p
		
	goto st142
	st142:
		if p++; p == pe {
			goto _test_eof142
		}
	st_case_142:
//line msg_parse.go:4223
		if 128 <= data[p] && data[p] <= 191 {
			goto st141
		}
		goto st0
tr206:
//line msg_parse.rl:55

			mark = p
		
	goto st143
	st143:
		if p++; p == pe {
			goto _test_eof143
		}
	st_case_143:
//line msg_parse.go:4239
		if 128 <= data[p] && data[p] <= 191 {
			goto st142
		}
		goto st0
tr207:
//line msg_parse.rl:55

			mark = p
		
//line msg_parse.rl:183

			ctype = string(data[mark:p])
		
	goto st144
tr215:
//line msg_parse.rl:183

			ctype = string(data[mark:p])
		
	goto st144
tr231:
//line msg_parse.rl:175

			msg.CallID = string(data[mark:p])
		
	goto st144
tr315:
//line msg_parse.rl:191

			msg.CSeqMethod = string(data[mark:p])
		
	goto st144
tr648:
//line msg_parse.rl:55

			mark = p
		
//line msg_parse.rl:207

			*viap, err = ParseVia(string(data[mark:p]))
			if err != nil { return nil, err }
			for *viap != nil { viap = &(*viap).Next }
		
	goto st144
tr656:
//line msg_parse.rl:207

			*viap, err = ParseVia(string(data[mark:p]))
			if err != nil { return nil, err }
			for *viap != nil { viap = &(*viap).Next }
		
	goto st144
	st144:
		if p++; p == pe {
			goto _test_eof144
		}
	st_case_144:
//line msg_parse.go:4297
		if data[p] == 10 {
			goto tr217
		}
		goto st0
tr221:
//line msg_parse.rl:55

			mark = p
		
	goto st145
	st145:
		if p++; p == pe {
			goto _test_eof145
		}
	st_case_145:
//line msg_parse.go:4313
		if data[p] == 10 {
			goto tr218
		}
		goto st0
tr218:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st146
	st146:
		if p++; p == pe {
			goto _test_eof146
		}
	st_case_146:
//line msg_parse.go:4330
		switch data[p] {
		case 9:
			goto st138
		case 32:
			goto st138
		}
		goto st0
	st147:
		if p++; p == pe {
			goto _test_eof147
		}
	st_case_147:
		if data[p] == 10 {
			goto tr219
		}
		goto st0
tr219:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st148
	st148:
		if p++; p == pe {
			goto _test_eof148
		}
	st_case_148:
//line msg_parse.go:4359
		switch data[p] {
		case 9:
			goto st149
		case 32:
			goto st149
		}
		goto st0
	st149:
		if p++; p == pe {
			goto _test_eof149
		}
	st_case_149:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st149
		case 32:
			goto st149
		case 269:
			goto tr207
		case 525:
			goto tr221
		}
		switch {
		case _widec < 224:
			switch {
			case _widec > 127:
				if 192 <= _widec && _widec <= 223 {
					goto tr202
				}
			case _widec >= 33:
				goto tr201
			}
		case _widec > 239:
			switch {
			case _widec < 248:
				if 240 <= _widec && _widec <= 247 {
					goto tr204
				}
			case _widec > 251:
				if 252 <= _widec && _widec <= 253 {
					goto tr206
				}
			default:
				goto tr205
			}
		default:
			goto tr203
		}
		goto st0
	st150:
		if p++; p == pe {
			goto _test_eof150
		}
	st_case_150:
		switch data[p] {
		case 76:
			goto st151
		case 108:
			goto st151
		}
		goto tr73
	st151:
		if p++; p == pe {
			goto _test_eof151
		}
	st_case_151:
		switch data[p] {
		case 76:
			goto st152
		case 108:
			goto st152
		}
		goto tr73
	st152:
		if p++; p == pe {
			goto _test_eof152
		}
	st_case_152:
		if data[p] == 45 {
			goto st153
		}
		goto tr73
	st153:
		if p++; p == pe {
			goto _test_eof153
		}
	st_case_153:
		switch data[p] {
		case 73:
			goto st154
		case 105:
			goto st154
		}
		goto tr73
	st154:
		if p++; p == pe {
			goto _test_eof154
		}
	st_case_154:
		switch data[p] {
		case 68:
			goto st155
		case 78:
			goto st163
		case 100:
			goto st155
		case 110:
			goto st163
		}
		goto tr73
	st155:
		if p++; p == pe {
			goto _test_eof155
		}
	st_case_155:
		switch data[p] {
		case 9:
			goto st155
		case 32:
			goto st155
		case 58:
			goto st156
		}
		goto st0
	st156:
		if p++; p == pe {
			goto _test_eof156
		}
	st_case_156:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st156
		case 32:
			goto st156
		case 37:
			goto tr229
		case 60:
			goto tr229
		case 525:
			goto st160
		}
		switch {
		case _widec < 62:
			switch {
			case _widec < 39:
				if 33 <= _widec && _widec <= 34 {
					goto tr229
				}
			case _widec > 43:
				if 45 <= _widec && _widec <= 58 {
					goto tr229
				}
			default:
				goto tr229
			}
		case _widec > 63:
			switch {
			case _widec < 95:
				if 65 <= _widec && _widec <= 93 {
					goto tr229
				}
			case _widec > 123:
				if 125 <= _widec && _widec <= 126 {
					goto tr229
				}
			default:
				goto tr229
			}
		default:
			goto tr229
		}
		goto st0
tr229:
//line msg_parse.rl:55

			mark = p
		
	goto st157
	st157:
		if p++; p == pe {
			goto _test_eof157
		}
	st_case_157:
//line msg_parse.go:4557
		switch data[p] {
		case 13:
			goto tr231
		case 37:
			goto st157
		case 60:
			goto st157
		case 64:
			goto st158
		}
		switch {
		case data[p] < 45:
			switch {
			case data[p] > 34:
				if 39 <= data[p] && data[p] <= 43 {
					goto st157
				}
			case data[p] >= 33:
				goto st157
			}
		case data[p] > 58:
			switch {
			case data[p] < 95:
				if 62 <= data[p] && data[p] <= 93 {
					goto st157
				}
			case data[p] > 123:
				if 125 <= data[p] && data[p] <= 126 {
					goto st157
				}
			default:
				goto st157
			}
		default:
			goto st157
		}
		goto st0
	st158:
		if p++; p == pe {
			goto _test_eof158
		}
	st_case_158:
		switch data[p] {
		case 37:
			goto st159
		case 60:
			goto st159
		}
		switch {
		case data[p] < 62:
			switch {
			case data[p] < 39:
				if 33 <= data[p] && data[p] <= 34 {
					goto st159
				}
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 58 {
					goto st159
				}
			default:
				goto st159
			}
		case data[p] > 63:
			switch {
			case data[p] < 95:
				if 65 <= data[p] && data[p] <= 93 {
					goto st159
				}
			case data[p] > 123:
				if 125 <= data[p] && data[p] <= 126 {
					goto st159
				}
			default:
				goto st159
			}
		default:
			goto st159
		}
		goto st0
	st159:
		if p++; p == pe {
			goto _test_eof159
		}
	st_case_159:
		switch data[p] {
		case 13:
			goto tr231
		case 37:
			goto st159
		case 60:
			goto st159
		}
		switch {
		case data[p] < 62:
			switch {
			case data[p] < 39:
				if 33 <= data[p] && data[p] <= 34 {
					goto st159
				}
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 58 {
					goto st159
				}
			default:
				goto st159
			}
		case data[p] > 63:
			switch {
			case data[p] < 95:
				if 65 <= data[p] && data[p] <= 93 {
					goto st159
				}
			case data[p] > 123:
				if 125 <= data[p] && data[p] <= 126 {
					goto st159
				}
			default:
				goto st159
			}
		default:
			goto st159
		}
		goto st0
	st160:
		if p++; p == pe {
			goto _test_eof160
		}
	st_case_160:
		if data[p] == 10 {
			goto tr235
		}
		goto st0
tr235:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st161
	st161:
		if p++; p == pe {
			goto _test_eof161
		}
	st_case_161:
//line msg_parse.go:4702
		switch data[p] {
		case 9:
			goto st162
		case 32:
			goto st162
		}
		goto st0
	st162:
		if p++; p == pe {
			goto _test_eof162
		}
	st_case_162:
		switch data[p] {
		case 9:
			goto st162
		case 32:
			goto st162
		case 37:
			goto tr229
		case 60:
			goto tr229
		}
		switch {
		case data[p] < 62:
			switch {
			case data[p] < 39:
				if 33 <= data[p] && data[p] <= 34 {
					goto tr229
				}
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 58 {
					goto tr229
				}
			default:
				goto tr229
			}
		case data[p] > 63:
			switch {
			case data[p] < 95:
				if 65 <= data[p] && data[p] <= 93 {
					goto tr229
				}
			case data[p] > 123:
				if 125 <= data[p] && data[p] <= 126 {
					goto tr229
				}
			default:
				goto tr229
			}
		default:
			goto tr229
		}
		goto st0
	st163:
		if p++; p == pe {
			goto _test_eof163
		}
	st_case_163:
		switch data[p] {
		case 70:
			goto st164
		case 102:
			goto st164
		}
		goto tr105
	st164:
		if p++; p == pe {
			goto _test_eof164
		}
	st_case_164:
		switch data[p] {
		case 79:
			goto st165
		case 111:
			goto st165
		}
		goto tr105
	st165:
		if p++; p == pe {
			goto _test_eof165
		}
	st_case_165:
		switch data[p] {
		case 9:
			goto tr239
		case 32:
			goto tr239
		case 58:
			goto tr240
		}
		goto st0
	st166:
		if p++; p == pe {
			goto _test_eof166
		}
	st_case_166:
		switch data[p] {
		case 78:
			goto st167
		case 110:
			goto st167
		}
		goto tr73
	st167:
		if p++; p == pe {
			goto _test_eof167
		}
	st_case_167:
		switch data[p] {
		case 84:
			goto st168
		case 116:
			goto st168
		}
		goto tr73
	st168:
		if p++; p == pe {
			goto _test_eof168
		}
	st_case_168:
		switch data[p] {
		case 65:
			goto st169
		case 69:
			goto st177
		case 97:
			goto st169
		case 101:
			goto st177
		}
		goto tr73
	st169:
		if p++; p == pe {
			goto _test_eof169
		}
	st_case_169:
		switch data[p] {
		case 67:
			goto st170
		case 99:
			goto st170
		}
		goto tr105
	st170:
		if p++; p == pe {
			goto _test_eof170
		}
	st_case_170:
		switch data[p] {
		case 84:
			goto st171
		case 116:
			goto st171
		}
		goto tr105
	st171:
		if p++; p == pe {
			goto _test_eof171
		}
	st_case_171:
		switch data[p] {
		case 9:
			goto tr247
		case 32:
			goto tr247
		case 58:
			goto tr248
		}
		goto st0
tr247:
//line msg_parse.rl:291
addr=&msg.Contact
	goto st172
tr355:
//line msg_parse.rl:292
addr=&msg.From
	goto st172
tr457:
//line msg_parse.rl:293
addr=&msg.PAssertedIdentity
	goto st172
tr524:
//line msg_parse.rl:294
addr=&msg.RecordRoute
	goto st172
tr549:
//line msg_parse.rl:295
addr=&msg.RemotePartyID
	goto st172
tr577:
//line msg_parse.rl:296
addr=&msg.Route
	goto st172
tr601:
//line msg_parse.rl:297
addr=&msg.To
	goto st172
	st172:
		if p++; p == pe {
			goto _test_eof172
		}
	st_case_172:
//line msg_parse.go:4905
		switch data[p] {
		case 9:
			goto st172
		case 32:
			goto st172
		case 58:
			goto st173
		}
		goto st0
tr248:
//line msg_parse.rl:291
addr=&msg.Contact
	goto st173
tr356:
//line msg_parse.rl:292
addr=&msg.From
	goto st173
tr458:
//line msg_parse.rl:293
addr=&msg.PAssertedIdentity
	goto st173
tr525:
//line msg_parse.rl:294
addr=&msg.RecordRoute
	goto st173
tr550:
//line msg_parse.rl:295
addr=&msg.RemotePartyID
	goto st173
tr578:
//line msg_parse.rl:296
addr=&msg.Route
	goto st173
tr602:
//line msg_parse.rl:297
addr=&msg.To
	goto st173
	st173:
		if p++; p == pe {
			goto _test_eof173
		}
	st_case_173:
//line msg_parse.go:4948
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st173
		case 32:
			goto st173
		case 269:
			goto tr251
		case 525:
			goto st174
		}
		switch {
		case _widec > 12:
			if 14 <= _widec {
				goto tr251
			}
		default:
			goto tr251
		}
		goto st0
	st174:
		if p++; p == pe {
			goto _test_eof174
		}
	st_case_174:
		if data[p] == 10 {
			goto tr253
		}
		goto st0
tr253:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st175
	st175:
		if p++; p == pe {
			goto _test_eof175
		}
	st_case_175:
//line msg_parse.go:4996
		switch data[p] {
		case 9:
			goto st176
		case 32:
			goto st176
		}
		goto st0
	st176:
		if p++; p == pe {
			goto _test_eof176
		}
	st_case_176:
		switch data[p] {
		case 9:
			goto st176
		case 32:
			goto st176
		}
		goto tr251
	st177:
		if p++; p == pe {
			goto _test_eof177
		}
	st_case_177:
		switch data[p] {
		case 78:
			goto st178
		case 110:
			goto st178
		}
		goto tr73
	st178:
		if p++; p == pe {
			goto _test_eof178
		}
	st_case_178:
		switch data[p] {
		case 84:
			goto st179
		case 116:
			goto st179
		}
		goto tr73
	st179:
		if p++; p == pe {
			goto _test_eof179
		}
	st_case_179:
		if data[p] == 45 {
			goto st180
		}
		goto tr73
	st180:
		if p++; p == pe {
			goto _test_eof180
		}
	st_case_180:
		switch data[p] {
		case 68:
			goto st181
		case 69:
			goto st192
		case 76:
			goto st200
		case 84:
			goto st218
		case 100:
			goto st181
		case 101:
			goto st192
		case 108:
			goto st200
		case 116:
			goto st218
		}
		goto tr73
	st181:
		if p++; p == pe {
			goto _test_eof181
		}
	st_case_181:
		switch data[p] {
		case 73:
			goto st182
		case 105:
			goto st182
		}
		goto tr105
	st182:
		if p++; p == pe {
			goto _test_eof182
		}
	st_case_182:
		switch data[p] {
		case 83:
			goto st183
		case 115:
			goto st183
		}
		goto tr105
	st183:
		if p++; p == pe {
			goto _test_eof183
		}
	st_case_183:
		switch data[p] {
		case 80:
			goto st184
		case 112:
			goto st184
		}
		goto tr105
	st184:
		if p++; p == pe {
			goto _test_eof184
		}
	st_case_184:
		switch data[p] {
		case 79:
			goto st185
		case 111:
			goto st185
		}
		goto tr105
	st185:
		if p++; p == pe {
			goto _test_eof185
		}
	st_case_185:
		switch data[p] {
		case 83:
			goto st186
		case 115:
			goto st186
		}
		goto tr105
	st186:
		if p++; p == pe {
			goto _test_eof186
		}
	st_case_186:
		switch data[p] {
		case 73:
			goto st187
		case 105:
			goto st187
		}
		goto tr105
	st187:
		if p++; p == pe {
			goto _test_eof187
		}
	st_case_187:
		switch data[p] {
		case 84:
			goto st188
		case 116:
			goto st188
		}
		goto tr105
	st188:
		if p++; p == pe {
			goto _test_eof188
		}
	st_case_188:
		switch data[p] {
		case 73:
			goto st189
		case 105:
			goto st189
		}
		goto tr105
	st189:
		if p++; p == pe {
			goto _test_eof189
		}
	st_case_189:
		switch data[p] {
		case 79:
			goto st190
		case 111:
			goto st190
		}
		goto tr105
	st190:
		if p++; p == pe {
			goto _test_eof190
		}
	st_case_190:
		switch data[p] {
		case 78:
			goto st191
		case 110:
			goto st191
		}
		goto tr105
	st191:
		if p++; p == pe {
			goto _test_eof191
		}
	st_case_191:
		switch data[p] {
		case 9:
			goto tr272
		case 32:
			goto tr272
		case 58:
			goto tr273
		}
		goto st0
	st192:
		if p++; p == pe {
			goto _test_eof192
		}
	st_case_192:
		switch data[p] {
		case 78:
			goto st193
		case 110:
			goto st193
		}
		goto tr105
	st193:
		if p++; p == pe {
			goto _test_eof193
		}
	st_case_193:
		switch data[p] {
		case 67:
			goto st194
		case 99:
			goto st194
		}
		goto tr105
	st194:
		if p++; p == pe {
			goto _test_eof194
		}
	st_case_194:
		switch data[p] {
		case 79:
			goto st195
		case 111:
			goto st195
		}
		goto tr105
	st195:
		if p++; p == pe {
			goto _test_eof195
		}
	st_case_195:
		switch data[p] {
		case 68:
			goto st196
		case 100:
			goto st196
		}
		goto tr105
	st196:
		if p++; p == pe {
			goto _test_eof196
		}
	st_case_196:
		switch data[p] {
		case 73:
			goto st197
		case 105:
			goto st197
		}
		goto tr105
	st197:
		if p++; p == pe {
			goto _test_eof197
		}
	st_case_197:
		switch data[p] {
		case 78:
			goto st198
		case 110:
			goto st198
		}
		goto tr105
	st198:
		if p++; p == pe {
			goto _test_eof198
		}
	st_case_198:
		switch data[p] {
		case 71:
			goto st199
		case 103:
			goto st199
		}
		goto tr105
	st199:
		if p++; p == pe {
			goto _test_eof199
		}
	st_case_199:
		switch data[p] {
		case 9:
			goto tr281
		case 32:
			goto tr281
		case 58:
			goto tr282
		}
		goto st0
	st200:
		if p++; p == pe {
			goto _test_eof200
		}
	st_case_200:
		switch data[p] {
		case 65:
			goto st201
		case 69:
			goto st208
		case 97:
			goto st201
		case 101:
			goto st208
		}
		goto tr73
	st201:
		if p++; p == pe {
			goto _test_eof201
		}
	st_case_201:
		switch data[p] {
		case 78:
			goto st202
		case 110:
			goto st202
		}
		goto tr105
	st202:
		if p++; p == pe {
			goto _test_eof202
		}
	st_case_202:
		switch data[p] {
		case 71:
			goto st203
		case 103:
			goto st203
		}
		goto tr105
	st203:
		if p++; p == pe {
			goto _test_eof203
		}
	st_case_203:
		switch data[p] {
		case 85:
			goto st204
		case 117:
			goto st204
		}
		goto tr105
	st204:
		if p++; p == pe {
			goto _test_eof204
		}
	st_case_204:
		switch data[p] {
		case 65:
			goto st205
		case 97:
			goto st205
		}
		goto tr105
	st205:
		if p++; p == pe {
			goto _test_eof205
		}
	st_case_205:
		switch data[p] {
		case 71:
			goto st206
		case 103:
			goto st206
		}
		goto tr105
	st206:
		if p++; p == pe {
			goto _test_eof206
		}
	st_case_206:
		switch data[p] {
		case 69:
			goto st207
		case 101:
			goto st207
		}
		goto tr105
	st207:
		if p++; p == pe {
			goto _test_eof207
		}
	st_case_207:
		switch data[p] {
		case 9:
			goto tr291
		case 32:
			goto tr291
		case 58:
			goto tr292
		}
		goto st0
	st208:
		if p++; p == pe {
			goto _test_eof208
		}
	st_case_208:
		switch data[p] {
		case 78:
			goto st209
		case 110:
			goto st209
		}
		goto tr293
	st209:
		if p++; p == pe {
			goto _test_eof209
		}
	st_case_209:
		switch data[p] {
		case 71:
			goto st210
		case 103:
			goto st210
		}
		goto tr293
	st210:
		if p++; p == pe {
			goto _test_eof210
		}
	st_case_210:
		switch data[p] {
		case 84:
			goto st211
		case 116:
			goto st211
		}
		goto tr293
	st211:
		if p++; p == pe {
			goto _test_eof211
		}
	st_case_211:
		switch data[p] {
		case 72:
			goto st212
		case 104:
			goto st212
		}
		goto tr293
	st212:
		if p++; p == pe {
			goto _test_eof212
		}
	st_case_212:
		switch data[p] {
		case 9:
			goto st212
		case 32:
			goto st212
		case 58:
			goto st213
		}
		goto st0
	st213:
		if p++; p == pe {
			goto _test_eof213
		}
	st_case_213:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st213
		case 32:
			goto st213
		case 525:
			goto st215
		}
		if 48 <= _widec && _widec <= 57 {
			goto tr299
		}
		goto st0
tr299:
//line msg_parse.rl:341
clen=0
//line msg_parse.rl:179

			clen = clen * 10 + (int(data[p]) - 0x30)
		
	goto st214
tr302:
//line msg_parse.rl:179

			clen = clen * 10 + (int(data[p]) - 0x30)
		
	goto st214
	st214:
		if p++; p == pe {
			goto _test_eof214
		}
	st_case_214:
//line msg_parse.go:5512
		if data[p] == 13 {
			goto st144
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr302
		}
		goto st0
	st215:
		if p++; p == pe {
			goto _test_eof215
		}
	st_case_215:
		if data[p] == 10 {
			goto tr303
		}
		goto st0
tr303:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st216
	st216:
		if p++; p == pe {
			goto _test_eof216
		}
	st_case_216:
//line msg_parse.go:5541
		switch data[p] {
		case 9:
			goto st217
		case 32:
			goto st217
		}
		goto st0
	st217:
		if p++; p == pe {
			goto _test_eof217
		}
	st_case_217:
		switch data[p] {
		case 9:
			goto st217
		case 32:
			goto st217
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr299
		}
		goto st0
	st218:
		if p++; p == pe {
			goto _test_eof218
		}
	st_case_218:
		switch data[p] {
		case 89:
			goto st219
		case 121:
			goto st219
		}
		goto tr293
	st219:
		if p++; p == pe {
			goto _test_eof219
		}
	st_case_219:
		switch data[p] {
		case 80:
			goto st220
		case 112:
			goto st220
		}
		goto tr293
	st220:
		if p++; p == pe {
			goto _test_eof220
		}
	st_case_220:
		switch data[p] {
		case 69:
			goto st136
		case 101:
			goto st136
		}
		goto tr293
	st221:
		if p++; p == pe {
			goto _test_eof221
		}
	st_case_221:
		switch data[p] {
		case 69:
			goto st222
		case 101:
			goto st222
		}
		goto tr293
	st222:
		if p++; p == pe {
			goto _test_eof222
		}
	st_case_222:
		switch data[p] {
		case 81:
			goto st223
		case 113:
			goto st223
		}
		goto tr293
	st223:
		if p++; p == pe {
			goto _test_eof223
		}
	st_case_223:
		switch data[p] {
		case 9:
			goto st223
		case 32:
			goto st223
		case 58:
			goto st224
		}
		goto st0
	st224:
		if p++; p == pe {
			goto _test_eof224
		}
	st_case_224:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st224
		case 32:
			goto st224
		case 525:
			goto st231
		}
		if 48 <= _widec && _widec <= 57 {
			goto tr310
		}
		goto st0
tr310:
//line msg_parse.rl:187

			msg.CSeq = msg.CSeq * 10 + (int(data[p]) - 0x30)
		
	goto st225
	st225:
		if p++; p == pe {
			goto _test_eof225
		}
	st_case_225:
//line msg_parse.go:5673
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st226
		case 32:
			goto st226
		case 525:
			goto st228
		}
		if 48 <= _widec && _widec <= 57 {
			goto tr310
		}
		goto st0
	st226:
		if p++; p == pe {
			goto _test_eof226
		}
	st_case_226:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st226
		case 32:
			goto st226
		case 33:
			goto tr314
		case 37:
			goto tr314
		case 39:
			goto tr314
		case 126:
			goto tr314
		case 525:
			goto st228
		}
		switch {
		case _widec < 48:
			switch {
			case _widec > 43:
				if 45 <= _widec && _widec <= 46 {
					goto tr314
				}
			case _widec >= 42:
				goto tr314
			}
		case _widec > 57:
			switch {
			case _widec > 90:
				if 95 <= _widec && _widec <= 122 {
					goto tr314
				}
			case _widec >= 65:
				goto tr314
			}
		default:
			goto tr314
		}
		goto st0
tr314:
//line msg_parse.rl:55

			mark = p
		
	goto st227
	st227:
		if p++; p == pe {
			goto _test_eof227
		}
	st_case_227:
//line msg_parse.go:5755
		switch data[p] {
		case 13:
			goto tr315
		case 33:
			goto st227
		case 37:
			goto st227
		case 39:
			goto st227
		case 126:
			goto st227
		}
		switch {
		case data[p] < 48:
			switch {
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 46 {
					goto st227
				}
			case data[p] >= 42:
				goto st227
			}
		case data[p] > 57:
			switch {
			case data[p] > 90:
				if 95 <= data[p] && data[p] <= 122 {
					goto st227
				}
			case data[p] >= 65:
				goto st227
			}
		default:
			goto st227
		}
		goto st0
	st228:
		if p++; p == pe {
			goto _test_eof228
		}
	st_case_228:
		if data[p] == 10 {
			goto tr317
		}
		goto st0
tr317:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st229
	st229:
		if p++; p == pe {
			goto _test_eof229
		}
	st_case_229:
//line msg_parse.go:5812
		switch data[p] {
		case 9:
			goto st230
		case 32:
			goto st230
		}
		goto st0
	st230:
		if p++; p == pe {
			goto _test_eof230
		}
	st_case_230:
		switch data[p] {
		case 9:
			goto st230
		case 32:
			goto st230
		case 33:
			goto tr314
		case 37:
			goto tr314
		case 39:
			goto tr314
		case 126:
			goto tr314
		}
		switch {
		case data[p] < 48:
			switch {
			case data[p] > 43:
				if 45 <= data[p] && data[p] <= 46 {
					goto tr314
				}
			case data[p] >= 42:
				goto tr314
			}
		case data[p] > 57:
			switch {
			case data[p] > 90:
				if 95 <= data[p] && data[p] <= 122 {
					goto tr314
				}
			case data[p] >= 65:
				goto tr314
			}
		default:
			goto tr314
		}
		goto st0
	st231:
		if p++; p == pe {
			goto _test_eof231
		}
	st_case_231:
		if data[p] == 10 {
			goto tr319
		}
		goto st0
tr319:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st232
	st232:
		if p++; p == pe {
			goto _test_eof232
		}
	st_case_232:
//line msg_parse.go:5883
		switch data[p] {
		case 9:
			goto st233
		case 32:
			goto st233
		}
		goto st0
	st233:
		if p++; p == pe {
			goto _test_eof233
		}
	st_case_233:
		switch data[p] {
		case 9:
			goto st233
		case 32:
			goto st233
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr310
		}
		goto st0
tr78:
//line msg_parse.rl:55

			mark = p
		
	goto st234
	st234:
		if p++; p == pe {
			goto _test_eof234
		}
	st_case_234:
//line msg_parse.go:5917
		switch data[p] {
		case 65:
			goto st235
		case 97:
			goto st235
		}
		goto tr105
	st235:
		if p++; p == pe {
			goto _test_eof235
		}
	st_case_235:
		switch data[p] {
		case 84:
			goto st236
		case 116:
			goto st236
		}
		goto tr105
	st236:
		if p++; p == pe {
			goto _test_eof236
		}
	st_case_236:
		switch data[p] {
		case 69:
			goto st237
		case 101:
			goto st237
		}
		goto tr105
	st237:
		if p++; p == pe {
			goto _test_eof237
		}
	st_case_237:
		switch data[p] {
		case 9:
			goto tr324
		case 32:
			goto tr324
		case 58:
			goto tr325
		}
		goto st0
tr79:
//line msg_parse.rl:55

			mark = p
		
	goto st238
	st238:
		if p++; p == pe {
			goto _test_eof238
		}
	st_case_238:
//line msg_parse.go:5974
		switch data[p] {
		case 9:
			goto tr281
		case 32:
			goto tr281
		case 58:
			goto tr282
		case 82:
			goto st239
		case 86:
			goto st248
		case 88:
			goto st252
		case 114:
			goto st239
		case 118:
			goto st248
		case 120:
			goto st252
		}
		goto tr293
	st239:
		if p++; p == pe {
			goto _test_eof239
		}
	st_case_239:
		switch data[p] {
		case 82:
			goto st240
		case 114:
			goto st240
		}
		goto tr105
	st240:
		if p++; p == pe {
			goto _test_eof240
		}
	st_case_240:
		switch data[p] {
		case 79:
			goto st241
		case 111:
			goto st241
		}
		goto tr105
	st241:
		if p++; p == pe {
			goto _test_eof241
		}
	st_case_241:
		switch data[p] {
		case 82:
			goto st242
		case 114:
			goto st242
		}
		goto tr105
	st242:
		if p++; p == pe {
			goto _test_eof242
		}
	st_case_242:
		if data[p] == 45 {
			goto st243
		}
		goto tr105
	st243:
		if p++; p == pe {
			goto _test_eof243
		}
	st_case_243:
		switch data[p] {
		case 73:
			goto st244
		case 105:
			goto st244
		}
		goto tr105
	st244:
		if p++; p == pe {
			goto _test_eof244
		}
	st_case_244:
		switch data[p] {
		case 78:
			goto st245
		case 110:
			goto st245
		}
		goto tr105
	st245:
		if p++; p == pe {
			goto _test_eof245
		}
	st_case_245:
		switch data[p] {
		case 70:
			goto st246
		case 102:
			goto st246
		}
		goto tr105
	st246:
		if p++; p == pe {
			goto _test_eof246
		}
	st_case_246:
		switch data[p] {
		case 79:
			goto st247
		case 111:
			goto st247
		}
		goto tr105
	st247:
		if p++; p == pe {
			goto _test_eof247
		}
	st_case_247:
		switch data[p] {
		case 9:
			goto tr337
		case 32:
			goto tr337
		case 58:
			goto tr338
		}
		goto st0
	st248:
		if p++; p == pe {
			goto _test_eof248
		}
	st_case_248:
		switch data[p] {
		case 69:
			goto st249
		case 101:
			goto st249
		}
		goto tr105
	st249:
		if p++; p == pe {
			goto _test_eof249
		}
	st_case_249:
		switch data[p] {
		case 78:
			goto st250
		case 110:
			goto st250
		}
		goto tr105
	st250:
		if p++; p == pe {
			goto _test_eof250
		}
	st_case_250:
		switch data[p] {
		case 84:
			goto st251
		case 116:
			goto st251
		}
		goto tr105
	st251:
		if p++; p == pe {
			goto _test_eof251
		}
	st_case_251:
		switch data[p] {
		case 9:
			goto tr342
		case 32:
			goto tr342
		case 58:
			goto tr343
		}
		goto st0
	st252:
		if p++; p == pe {
			goto _test_eof252
		}
	st_case_252:
		switch data[p] {
		case 80:
			goto st253
		case 112:
			goto st253
		}
		goto tr293
	st253:
		if p++; p == pe {
			goto _test_eof253
		}
	st_case_253:
		switch data[p] {
		case 73:
			goto st254
		case 105:
			goto st254
		}
		goto tr293
	st254:
		if p++; p == pe {
			goto _test_eof254
		}
	st_case_254:
		switch data[p] {
		case 82:
			goto st255
		case 114:
			goto st255
		}
		goto tr293
	st255:
		if p++; p == pe {
			goto _test_eof255
		}
	st_case_255:
		switch data[p] {
		case 69:
			goto st256
		case 101:
			goto st256
		}
		goto tr293
	st256:
		if p++; p == pe {
			goto _test_eof256
		}
	st_case_256:
		switch data[p] {
		case 83:
			goto st257
		case 115:
			goto st257
		}
		goto tr293
	st257:
		if p++; p == pe {
			goto _test_eof257
		}
	st_case_257:
		switch data[p] {
		case 9:
			goto st257
		case 32:
			goto st257
		case 58:
			goto st258
		}
		goto st0
	st258:
		if p++; p == pe {
			goto _test_eof258
		}
	st_case_258:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st258
		case 32:
			goto st258
		case 525:
			goto st260
		}
		if 48 <= _widec && _widec <= 57 {
			goto tr350
		}
		goto st0
tr350:
//line msg_parse.rl:344
msg.Expires=0
//line msg_parse.rl:195

			msg.Expires = msg.Expires * 10 + (int(data[p]) - 0x30)
		
	goto st259
tr352:
//line msg_parse.rl:195

			msg.Expires = msg.Expires * 10 + (int(data[p]) - 0x30)
		
	goto st259
	st259:
		if p++; p == pe {
			goto _test_eof259
		}
	st_case_259:
//line msg_parse.go:6270
		if data[p] == 13 {
			goto st144
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr352
		}
		goto st0
	st260:
		if p++; p == pe {
			goto _test_eof260
		}
	st_case_260:
		if data[p] == 10 {
			goto tr353
		}
		goto st0
tr353:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st261
	st261:
		if p++; p == pe {
			goto _test_eof261
		}
	st_case_261:
//line msg_parse.go:6299
		switch data[p] {
		case 9:
			goto st262
		case 32:
			goto st262
		}
		goto st0
	st262:
		if p++; p == pe {
			goto _test_eof262
		}
	st_case_262:
		switch data[p] {
		case 9:
			goto st262
		case 32:
			goto st262
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr350
		}
		goto st0
tr80:
//line msg_parse.rl:55

			mark = p
		
	goto st263
	st263:
		if p++; p == pe {
			goto _test_eof263
		}
	st_case_263:
//line msg_parse.go:6333
		switch data[p] {
		case 9:
			goto tr355
		case 32:
			goto tr355
		case 58:
			goto tr356
		case 82:
			goto st264
		case 114:
			goto st264
		}
		goto st0
	st264:
		if p++; p == pe {
			goto _test_eof264
		}
	st_case_264:
		switch data[p] {
		case 79:
			goto st265
		case 111:
			goto st265
		}
		goto tr105
	st265:
		if p++; p == pe {
			goto _test_eof265
		}
	st_case_265:
		switch data[p] {
		case 77:
			goto st266
		case 109:
			goto st266
		}
		goto tr105
	st266:
		if p++; p == pe {
			goto _test_eof266
		}
	st_case_266:
		switch data[p] {
		case 9:
			goto tr355
		case 32:
			goto tr355
		case 58:
			goto tr356
		}
		goto st0
tr81:
//line msg_parse.rl:55

			mark = p
		
	goto st267
	st267:
		if p++; p == pe {
			goto _test_eof267
		}
	st_case_267:
//line msg_parse.go:6396
		switch data[p] {
		case 9:
			goto st155
		case 32:
			goto st155
		case 58:
			goto st156
		case 78:
			goto st268
		case 110:
			goto st268
		}
		goto tr105
	st268:
		if p++; p == pe {
			goto _test_eof268
		}
	st_case_268:
		if data[p] == 45 {
			goto st269
		}
		goto tr105
	st269:
		if p++; p == pe {
			goto _test_eof269
		}
	st_case_269:
		switch data[p] {
		case 82:
			goto st270
		case 114:
			goto st270
		}
		goto tr105
	st270:
		if p++; p == pe {
			goto _test_eof270
		}
	st_case_270:
		switch data[p] {
		case 69:
			goto st271
		case 101:
			goto st271
		}
		goto tr105
	st271:
		if p++; p == pe {
			goto _test_eof271
		}
	st_case_271:
		switch data[p] {
		case 80:
			goto st272
		case 112:
			goto st272
		}
		goto tr105
	st272:
		if p++; p == pe {
			goto _test_eof272
		}
	st_case_272:
		switch data[p] {
		case 76:
			goto st273
		case 108:
			goto st273
		}
		goto tr105
	st273:
		if p++; p == pe {
			goto _test_eof273
		}
	st_case_273:
		switch data[p] {
		case 89:
			goto st274
		case 121:
			goto st274
		}
		goto tr105
	st274:
		if p++; p == pe {
			goto _test_eof274
		}
	st_case_274:
		if data[p] == 45 {
			goto st275
		}
		goto tr105
	st275:
		if p++; p == pe {
			goto _test_eof275
		}
	st_case_275:
		switch data[p] {
		case 84:
			goto st276
		case 116:
			goto st276
		}
		goto tr105
	st276:
		if p++; p == pe {
			goto _test_eof276
		}
	st_case_276:
		switch data[p] {
		case 79:
			goto st277
		case 111:
			goto st277
		}
		goto tr105
	st277:
		if p++; p == pe {
			goto _test_eof277
		}
	st_case_277:
		switch data[p] {
		case 9:
			goto tr370
		case 32:
			goto tr370
		case 58:
			goto tr371
		}
		goto st0
tr82:
//line msg_parse.rl:55

			mark = p
		
	goto st278
	st278:
		if p++; p == pe {
			goto _test_eof278
		}
	st_case_278:
//line msg_parse.go:6537
		switch data[p] {
		case 9:
			goto tr372
		case 32:
			goto tr372
		case 58:
			goto tr373
		}
		goto st0
	st279:
		if p++; p == pe {
			goto _test_eof279
		}
	st_case_279:
		switch data[p] {
		case 9:
			goto st279
		case 32:
			goto st279
		case 58:
			goto st280
		}
		goto st0
	st280:
		if p++; p == pe {
			goto _test_eof280
		}
	st_case_280:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st280
		case 32:
			goto st280
		case 525:
			goto st282
		}
		if 48 <= _widec && _widec <= 57 {
			goto tr375
		}
		goto st0
tr375:
//line msg_parse.rl:341
clen=0
//line msg_parse.rl:179

			clen = clen * 10 + (int(data[p]) - 0x30)
		
//line msg_parse.rl:344
msg.Expires=0
//line msg_parse.rl:195

			msg.Expires = msg.Expires * 10 + (int(data[p]) - 0x30)
		
//line msg_parse.rl:345
msg.MaxForwards=0
//line msg_parse.rl:199

			msg.MaxForwards = msg.MaxForwards * 10 + (int(data[p]) - 0x30)
		
//line msg_parse.rl:346
msg.MinExpires=0
//line msg_parse.rl:203

			msg.MinExpires = msg.MinExpires * 10 + (int(data[p]) - 0x30)
		
	goto st281
tr377:
//line msg_parse.rl:179

			clen = clen * 10 + (int(data[p]) - 0x30)
		
//line msg_parse.rl:195

			msg.Expires = msg.Expires * 10 + (int(data[p]) - 0x30)
		
//line msg_parse.rl:199

			msg.MaxForwards = msg.MaxForwards * 10 + (int(data[p]) - 0x30)
		
//line msg_parse.rl:203

			msg.MinExpires = msg.MinExpires * 10 + (int(data[p]) - 0x30)
		
	goto st281
	st281:
		if p++; p == pe {
			goto _test_eof281
		}
	st_case_281:
//line msg_parse.go:6634
		if data[p] == 13 {
			goto st144
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr377
		}
		goto st0
	st282:
		if p++; p == pe {
			goto _test_eof282
		}
	st_case_282:
		if data[p] == 10 {
			goto tr378
		}
		goto st0
tr378:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st283
	st283:
		if p++; p == pe {
			goto _test_eof283
		}
	st_case_283:
//line msg_parse.go:6663
		switch data[p] {
		case 9:
			goto st284
		case 32:
			goto st284
		}
		goto st0
	st284:
		if p++; p == pe {
			goto _test_eof284
		}
	st_case_284:
		switch data[p] {
		case 9:
			goto st284
		case 32:
			goto st284
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr375
		}
		goto st0
tr84:
//line msg_parse.rl:55

			mark = p
		
	goto st285
	st285:
		if p++; p == pe {
			goto _test_eof285
		}
	st_case_285:
//line msg_parse.go:6697
		switch data[p] {
		case 9:
			goto tr247
		case 32:
			goto tr247
		case 58:
			goto tr248
		case 65:
			goto st286
		case 73:
			goto st302
		case 97:
			goto st286
		case 105:
			goto st302
		}
		goto tr73
	st286:
		if p++; p == pe {
			goto _test_eof286
		}
	st_case_286:
		switch data[p] {
		case 88:
			goto st287
		case 120:
			goto st287
		}
		goto tr293
	st287:
		if p++; p == pe {
			goto _test_eof287
		}
	st_case_287:
		if data[p] == 45 {
			goto st288
		}
		goto tr293
	st288:
		if p++; p == pe {
			goto _test_eof288
		}
	st_case_288:
		switch data[p] {
		case 70:
			goto st289
		case 102:
			goto st289
		}
		goto tr293
	st289:
		if p++; p == pe {
			goto _test_eof289
		}
	st_case_289:
		switch data[p] {
		case 79:
			goto st290
		case 111:
			goto st290
		}
		goto tr293
	st290:
		if p++; p == pe {
			goto _test_eof290
		}
	st_case_290:
		switch data[p] {
		case 82:
			goto st291
		case 114:
			goto st291
		}
		goto tr293
	st291:
		if p++; p == pe {
			goto _test_eof291
		}
	st_case_291:
		switch data[p] {
		case 87:
			goto st292
		case 119:
			goto st292
		}
		goto tr293
	st292:
		if p++; p == pe {
			goto _test_eof292
		}
	st_case_292:
		switch data[p] {
		case 65:
			goto st293
		case 97:
			goto st293
		}
		goto tr293
	st293:
		if p++; p == pe {
			goto _test_eof293
		}
	st_case_293:
		switch data[p] {
		case 82:
			goto st294
		case 114:
			goto st294
		}
		goto tr293
	st294:
		if p++; p == pe {
			goto _test_eof294
		}
	st_case_294:
		switch data[p] {
		case 68:
			goto st295
		case 100:
			goto st295
		}
		goto tr293
	st295:
		if p++; p == pe {
			goto _test_eof295
		}
	st_case_295:
		switch data[p] {
		case 83:
			goto st296
		case 115:
			goto st296
		}
		goto tr293
	st296:
		if p++; p == pe {
			goto _test_eof296
		}
	st_case_296:
		switch data[p] {
		case 9:
			goto st296
		case 32:
			goto st296
		case 58:
			goto st297
		}
		goto st0
	st297:
		if p++; p == pe {
			goto _test_eof297
		}
	st_case_297:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st297
		case 32:
			goto st297
		case 525:
			goto st299
		}
		if 48 <= _widec && _widec <= 57 {
			goto tr393
		}
		goto st0
tr393:
//line msg_parse.rl:345
msg.MaxForwards=0
//line msg_parse.rl:199

			msg.MaxForwards = msg.MaxForwards * 10 + (int(data[p]) - 0x30)
		
	goto st298
tr395:
//line msg_parse.rl:199

			msg.MaxForwards = msg.MaxForwards * 10 + (int(data[p]) - 0x30)
		
	goto st298
	st298:
		if p++; p == pe {
			goto _test_eof298
		}
	st_case_298:
//line msg_parse.go:6889
		if data[p] == 13 {
			goto st144
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr395
		}
		goto st0
	st299:
		if p++; p == pe {
			goto _test_eof299
		}
	st_case_299:
		if data[p] == 10 {
			goto tr396
		}
		goto st0
tr396:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st300
	st300:
		if p++; p == pe {
			goto _test_eof300
		}
	st_case_300:
//line msg_parse.go:6918
		switch data[p] {
		case 9:
			goto st301
		case 32:
			goto st301
		}
		goto st0
	st301:
		if p++; p == pe {
			goto _test_eof301
		}
	st_case_301:
		switch data[p] {
		case 9:
			goto st301
		case 32:
			goto st301
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr393
		}
		goto st0
	st302:
		if p++; p == pe {
			goto _test_eof302
		}
	st_case_302:
		switch data[p] {
		case 77:
			goto st303
		case 78:
			goto st313
		case 109:
			goto st303
		case 110:
			goto st313
		}
		goto tr73
	st303:
		if p++; p == pe {
			goto _test_eof303
		}
	st_case_303:
		switch data[p] {
		case 69:
			goto st304
		case 101:
			goto st304
		}
		goto tr105
	st304:
		if p++; p == pe {
			goto _test_eof304
		}
	st_case_304:
		if data[p] == 45 {
			goto st305
		}
		goto tr105
	st305:
		if p++; p == pe {
			goto _test_eof305
		}
	st_case_305:
		switch data[p] {
		case 86:
			goto st306
		case 118:
			goto st306
		}
		goto tr105
	st306:
		if p++; p == pe {
			goto _test_eof306
		}
	st_case_306:
		switch data[p] {
		case 69:
			goto st307
		case 101:
			goto st307
		}
		goto tr105
	st307:
		if p++; p == pe {
			goto _test_eof307
		}
	st_case_307:
		switch data[p] {
		case 82:
			goto st308
		case 114:
			goto st308
		}
		goto tr105
	st308:
		if p++; p == pe {
			goto _test_eof308
		}
	st_case_308:
		switch data[p] {
		case 83:
			goto st309
		case 115:
			goto st309
		}
		goto tr105
	st309:
		if p++; p == pe {
			goto _test_eof309
		}
	st_case_309:
		switch data[p] {
		case 73:
			goto st310
		case 105:
			goto st310
		}
		goto tr105
	st310:
		if p++; p == pe {
			goto _test_eof310
		}
	st_case_310:
		switch data[p] {
		case 79:
			goto st311
		case 111:
			goto st311
		}
		goto tr105
	st311:
		if p++; p == pe {
			goto _test_eof311
		}
	st_case_311:
		switch data[p] {
		case 78:
			goto st312
		case 110:
			goto st312
		}
		goto tr105
	st312:
		if p++; p == pe {
			goto _test_eof312
		}
	st_case_312:
		switch data[p] {
		case 9:
			goto tr409
		case 32:
			goto tr409
		case 58:
			goto tr410
		}
		goto st0
	st313:
		if p++; p == pe {
			goto _test_eof313
		}
	st_case_313:
		if data[p] == 45 {
			goto st314
		}
		goto tr293
	st314:
		if p++; p == pe {
			goto _test_eof314
		}
	st_case_314:
		switch data[p] {
		case 69:
			goto st315
		case 101:
			goto st315
		}
		goto tr293
	st315:
		if p++; p == pe {
			goto _test_eof315
		}
	st_case_315:
		switch data[p] {
		case 88:
			goto st316
		case 120:
			goto st316
		}
		goto tr293
	st316:
		if p++; p == pe {
			goto _test_eof316
		}
	st_case_316:
		switch data[p] {
		case 80:
			goto st317
		case 112:
			goto st317
		}
		goto tr293
	st317:
		if p++; p == pe {
			goto _test_eof317
		}
	st_case_317:
		switch data[p] {
		case 73:
			goto st318
		case 105:
			goto st318
		}
		goto tr293
	st318:
		if p++; p == pe {
			goto _test_eof318
		}
	st_case_318:
		switch data[p] {
		case 82:
			goto st319
		case 114:
			goto st319
		}
		goto tr293
	st319:
		if p++; p == pe {
			goto _test_eof319
		}
	st_case_319:
		switch data[p] {
		case 69:
			goto st320
		case 101:
			goto st320
		}
		goto tr293
	st320:
		if p++; p == pe {
			goto _test_eof320
		}
	st_case_320:
		switch data[p] {
		case 83:
			goto st321
		case 115:
			goto st321
		}
		goto tr293
	st321:
		if p++; p == pe {
			goto _test_eof321
		}
	st_case_321:
		switch data[p] {
		case 9:
			goto st321
		case 32:
			goto st321
		case 58:
			goto st322
		}
		goto st0
	st322:
		if p++; p == pe {
			goto _test_eof322
		}
	st_case_322:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st322
		case 32:
			goto st322
		case 525:
			goto st324
		}
		if 48 <= _widec && _widec <= 57 {
			goto tr420
		}
		goto st0
tr420:
//line msg_parse.rl:346
msg.MinExpires=0
//line msg_parse.rl:203

			msg.MinExpires = msg.MinExpires * 10 + (int(data[p]) - 0x30)
		
	goto st323
tr422:
//line msg_parse.rl:203

			msg.MinExpires = msg.MinExpires * 10 + (int(data[p]) - 0x30)
		
	goto st323
	st323:
		if p++; p == pe {
			goto _test_eof323
		}
	st_case_323:
//line msg_parse.go:7226
		if data[p] == 13 {
			goto st144
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr422
		}
		goto st0
	st324:
		if p++; p == pe {
			goto _test_eof324
		}
	st_case_324:
		if data[p] == 10 {
			goto tr423
		}
		goto st0
tr423:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st325
	st325:
		if p++; p == pe {
			goto _test_eof325
		}
	st_case_325:
//line msg_parse.go:7255
		switch data[p] {
		case 9:
			goto st326
		case 32:
			goto st326
		}
		goto st0
	st326:
		if p++; p == pe {
			goto _test_eof326
		}
	st_case_326:
		switch data[p] {
		case 9:
			goto st326
		case 32:
			goto st326
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto tr420
		}
		goto st0
tr85:
//line msg_parse.rl:55

			mark = p
		
	goto st327
	st327:
		if p++; p == pe {
			goto _test_eof327
		}
	st_case_327:
//line msg_parse.go:7289
		switch data[p] {
		case 9:
			goto tr342
		case 32:
			goto tr342
		case 58:
			goto tr343
		case 82:
			goto st328
		case 114:
			goto st328
		}
		goto st0
	st328:
		if p++; p == pe {
			goto _test_eof328
		}
	st_case_328:
		switch data[p] {
		case 71:
			goto st329
		case 103:
			goto st329
		}
		goto tr105
	st329:
		if p++; p == pe {
			goto _test_eof329
		}
	st_case_329:
		switch data[p] {
		case 65:
			goto st330
		case 97:
			goto st330
		}
		goto tr105
	st330:
		if p++; p == pe {
			goto _test_eof330
		}
	st_case_330:
		switch data[p] {
		case 78:
			goto st331
		case 110:
			goto st331
		}
		goto tr105
	st331:
		if p++; p == pe {
			goto _test_eof331
		}
	st_case_331:
		switch data[p] {
		case 73:
			goto st332
		case 105:
			goto st332
		}
		goto tr105
	st332:
		if p++; p == pe {
			goto _test_eof332
		}
	st_case_332:
		switch data[p] {
		case 90:
			goto st333
		case 122:
			goto st333
		}
		goto tr105
	st333:
		if p++; p == pe {
			goto _test_eof333
		}
	st_case_333:
		switch data[p] {
		case 65:
			goto st334
		case 97:
			goto st334
		}
		goto tr105
	st334:
		if p++; p == pe {
			goto _test_eof334
		}
	st_case_334:
		switch data[p] {
		case 84:
			goto st335
		case 116:
			goto st335
		}
		goto tr105
	st335:
		if p++; p == pe {
			goto _test_eof335
		}
	st_case_335:
		switch data[p] {
		case 73:
			goto st336
		case 105:
			goto st336
		}
		goto tr105
	st336:
		if p++; p == pe {
			goto _test_eof336
		}
	st_case_336:
		switch data[p] {
		case 79:
			goto st337
		case 111:
			goto st337
		}
		goto tr105
	st337:
		if p++; p == pe {
			goto _test_eof337
		}
	st_case_337:
		switch data[p] {
		case 78:
			goto st338
		case 110:
			goto st338
		}
		goto tr105
	st338:
		if p++; p == pe {
			goto _test_eof338
		}
	st_case_338:
		switch data[p] {
		case 9:
			goto tr436
		case 32:
			goto tr436
		case 58:
			goto tr437
		}
		goto st0
tr86:
//line msg_parse.rl:55

			mark = p
		
	goto st339
	st339:
		if p++; p == pe {
			goto _test_eof339
		}
	st_case_339:
//line msg_parse.go:7448
		switch data[p] {
		case 45:
			goto st340
		case 82:
			goto st358
		case 114:
			goto st358
		}
		goto tr105
	st340:
		if p++; p == pe {
			goto _test_eof340
		}
	st_case_340:
		switch data[p] {
		case 65:
			goto st341
		case 97:
			goto st341
		}
		goto tr105
	st341:
		if p++; p == pe {
			goto _test_eof341
		}
	st_case_341:
		switch data[p] {
		case 83:
			goto st342
		case 115:
			goto st342
		}
		goto tr105
	st342:
		if p++; p == pe {
			goto _test_eof342
		}
	st_case_342:
		switch data[p] {
		case 83:
			goto st343
		case 115:
			goto st343
		}
		goto tr105
	st343:
		if p++; p == pe {
			goto _test_eof343
		}
	st_case_343:
		switch data[p] {
		case 69:
			goto st344
		case 101:
			goto st344
		}
		goto tr105
	st344:
		if p++; p == pe {
			goto _test_eof344
		}
	st_case_344:
		switch data[p] {
		case 82:
			goto st345
		case 114:
			goto st345
		}
		goto tr105
	st345:
		if p++; p == pe {
			goto _test_eof345
		}
	st_case_345:
		switch data[p] {
		case 84:
			goto st346
		case 116:
			goto st346
		}
		goto tr105
	st346:
		if p++; p == pe {
			goto _test_eof346
		}
	st_case_346:
		switch data[p] {
		case 69:
			goto st347
		case 101:
			goto st347
		}
		goto tr105
	st347:
		if p++; p == pe {
			goto _test_eof347
		}
	st_case_347:
		switch data[p] {
		case 68:
			goto st348
		case 100:
			goto st348
		}
		goto tr105
	st348:
		if p++; p == pe {
			goto _test_eof348
		}
	st_case_348:
		if data[p] == 45 {
			goto st349
		}
		goto tr105
	st349:
		if p++; p == pe {
			goto _test_eof349
		}
	st_case_349:
		switch data[p] {
		case 73:
			goto st350
		case 105:
			goto st350
		}
		goto tr105
	st350:
		if p++; p == pe {
			goto _test_eof350
		}
	st_case_350:
		switch data[p] {
		case 68:
			goto st351
		case 100:
			goto st351
		}
		goto tr105
	st351:
		if p++; p == pe {
			goto _test_eof351
		}
	st_case_351:
		switch data[p] {
		case 69:
			goto st352
		case 101:
			goto st352
		}
		goto tr105
	st352:
		if p++; p == pe {
			goto _test_eof352
		}
	st_case_352:
		switch data[p] {
		case 78:
			goto st353
		case 110:
			goto st353
		}
		goto tr105
	st353:
		if p++; p == pe {
			goto _test_eof353
		}
	st_case_353:
		switch data[p] {
		case 84:
			goto st354
		case 116:
			goto st354
		}
		goto tr105
	st354:
		if p++; p == pe {
			goto _test_eof354
		}
	st_case_354:
		switch data[p] {
		case 73:
			goto st355
		case 105:
			goto st355
		}
		goto tr105
	st355:
		if p++; p == pe {
			goto _test_eof355
		}
	st_case_355:
		switch data[p] {
		case 84:
			goto st356
		case 116:
			goto st356
		}
		goto tr105
	st356:
		if p++; p == pe {
			goto _test_eof356
		}
	st_case_356:
		switch data[p] {
		case 89:
			goto st357
		case 121:
			goto st357
		}
		goto tr105
	st357:
		if p++; p == pe {
			goto _test_eof357
		}
	st_case_357:
		switch data[p] {
		case 9:
			goto tr457
		case 32:
			goto tr457
		case 58:
			goto tr458
		}
		goto st0
	st358:
		if p++; p == pe {
			goto _test_eof358
		}
	st_case_358:
		switch data[p] {
		case 73:
			goto st359
		case 79:
			goto st365
		case 105:
			goto st359
		case 111:
			goto st365
		}
		goto tr105
	st359:
		if p++; p == pe {
			goto _test_eof359
		}
	st_case_359:
		switch data[p] {
		case 79:
			goto st360
		case 111:
			goto st360
		}
		goto tr105
	st360:
		if p++; p == pe {
			goto _test_eof360
		}
	st_case_360:
		switch data[p] {
		case 82:
			goto st361
		case 114:
			goto st361
		}
		goto tr105
	st361:
		if p++; p == pe {
			goto _test_eof361
		}
	st_case_361:
		switch data[p] {
		case 73:
			goto st362
		case 105:
			goto st362
		}
		goto tr105
	st362:
		if p++; p == pe {
			goto _test_eof362
		}
	st_case_362:
		switch data[p] {
		case 84:
			goto st363
		case 116:
			goto st363
		}
		goto tr105
	st363:
		if p++; p == pe {
			goto _test_eof363
		}
	st_case_363:
		switch data[p] {
		case 89:
			goto st364
		case 121:
			goto st364
		}
		goto tr105
	st364:
		if p++; p == pe {
			goto _test_eof364
		}
	st_case_364:
		switch data[p] {
		case 9:
			goto tr466
		case 32:
			goto tr466
		case 58:
			goto tr467
		}
		goto st0
	st365:
		if p++; p == pe {
			goto _test_eof365
		}
	st_case_365:
		switch data[p] {
		case 88:
			goto st366
		case 120:
			goto st366
		}
		goto tr105
	st366:
		if p++; p == pe {
			goto _test_eof366
		}
	st_case_366:
		switch data[p] {
		case 89:
			goto st367
		case 121:
			goto st367
		}
		goto tr105
	st367:
		if p++; p == pe {
			goto _test_eof367
		}
	st_case_367:
		if data[p] == 45 {
			goto st368
		}
		goto tr105
	st368:
		if p++; p == pe {
			goto _test_eof368
		}
	st_case_368:
		switch data[p] {
		case 65:
			goto st369
		case 82:
			goto st390
		case 97:
			goto st369
		case 114:
			goto st390
		}
		goto tr105
	st369:
		if p++; p == pe {
			goto _test_eof369
		}
	st_case_369:
		switch data[p] {
		case 85:
			goto st370
		case 117:
			goto st370
		}
		goto tr105
	st370:
		if p++; p == pe {
			goto _test_eof370
		}
	st_case_370:
		switch data[p] {
		case 84:
			goto st371
		case 116:
			goto st371
		}
		goto tr105
	st371:
		if p++; p == pe {
			goto _test_eof371
		}
	st_case_371:
		switch data[p] {
		case 72:
			goto st372
		case 104:
			goto st372
		}
		goto tr105
	st372:
		if p++; p == pe {
			goto _test_eof372
		}
	st_case_372:
		switch data[p] {
		case 69:
			goto st373
		case 79:
			goto st381
		case 101:
			goto st373
		case 111:
			goto st381
		}
		goto tr105
	st373:
		if p++; p == pe {
			goto _test_eof373
		}
	st_case_373:
		switch data[p] {
		case 78:
			goto st374
		case 110:
			goto st374
		}
		goto tr105
	st374:
		if p++; p == pe {
			goto _test_eof374
		}
	st_case_374:
		switch data[p] {
		case 84:
			goto st375
		case 116:
			goto st375
		}
		goto tr105
	st375:
		if p++; p == pe {
			goto _test_eof375
		}
	st_case_375:
		switch data[p] {
		case 73:
			goto st376
		case 105:
			goto st376
		}
		goto tr105
	st376:
		if p++; p == pe {
			goto _test_eof376
		}
	st_case_376:
		switch data[p] {
		case 67:
			goto st377
		case 99:
			goto st377
		}
		goto tr105
	st377:
		if p++; p == pe {
			goto _test_eof377
		}
	st_case_377:
		switch data[p] {
		case 65:
			goto st378
		case 97:
			goto st378
		}
		goto tr105
	st378:
		if p++; p == pe {
			goto _test_eof378
		}
	st_case_378:
		switch data[p] {
		case 84:
			goto st379
		case 116:
			goto st379
		}
		goto tr105
	st379:
		if p++; p == pe {
			goto _test_eof379
		}
	st_case_379:
		switch data[p] {
		case 69:
			goto st380
		case 101:
			goto st380
		}
		goto tr105
	st380:
		if p++; p == pe {
			goto _test_eof380
		}
	st_case_380:
		switch data[p] {
		case 9:
			goto tr485
		case 32:
			goto tr485
		case 58:
			goto tr486
		}
		goto st0
	st381:
		if p++; p == pe {
			goto _test_eof381
		}
	st_case_381:
		switch data[p] {
		case 82:
			goto st382
		case 114:
			goto st382
		}
		goto tr105
	st382:
		if p++; p == pe {
			goto _test_eof382
		}
	st_case_382:
		switch data[p] {
		case 73:
			goto st383
		case 105:
			goto st383
		}
		goto tr105
	st383:
		if p++; p == pe {
			goto _test_eof383
		}
	st_case_383:
		switch data[p] {
		case 90:
			goto st384
		case 122:
			goto st384
		}
		goto tr105
	st384:
		if p++; p == pe {
			goto _test_eof384
		}
	st_case_384:
		switch data[p] {
		case 65:
			goto st385
		case 97:
			goto st385
		}
		goto tr105
	st385:
		if p++; p == pe {
			goto _test_eof385
		}
	st_case_385:
		switch data[p] {
		case 84:
			goto st386
		case 116:
			goto st386
		}
		goto tr105
	st386:
		if p++; p == pe {
			goto _test_eof386
		}
	st_case_386:
		switch data[p] {
		case 73:
			goto st387
		case 105:
			goto st387
		}
		goto tr105
	st387:
		if p++; p == pe {
			goto _test_eof387
		}
	st_case_387:
		switch data[p] {
		case 79:
			goto st388
		case 111:
			goto st388
		}
		goto tr105
	st388:
		if p++; p == pe {
			goto _test_eof388
		}
	st_case_388:
		switch data[p] {
		case 78:
			goto st389
		case 110:
			goto st389
		}
		goto tr105
	st389:
		if p++; p == pe {
			goto _test_eof389
		}
	st_case_389:
		switch data[p] {
		case 9:
			goto tr495
		case 32:
			goto tr495
		case 58:
			goto tr496
		}
		goto st0
	st390:
		if p++; p == pe {
			goto _test_eof390
		}
	st_case_390:
		switch data[p] {
		case 69:
			goto st391
		case 101:
			goto st391
		}
		goto tr105
	st391:
		if p++; p == pe {
			goto _test_eof391
		}
	st_case_391:
		switch data[p] {
		case 81:
			goto st392
		case 113:
			goto st392
		}
		goto tr105
	st392:
		if p++; p == pe {
			goto _test_eof392
		}
	st_case_392:
		switch data[p] {
		case 85:
			goto st393
		case 117:
			goto st393
		}
		goto tr105
	st393:
		if p++; p == pe {
			goto _test_eof393
		}
	st_case_393:
		switch data[p] {
		case 73:
			goto st394
		case 105:
			goto st394
		}
		goto tr105
	st394:
		if p++; p == pe {
			goto _test_eof394
		}
	st_case_394:
		switch data[p] {
		case 82:
			goto st395
		case 114:
			goto st395
		}
		goto tr105
	st395:
		if p++; p == pe {
			goto _test_eof395
		}
	st_case_395:
		switch data[p] {
		case 69:
			goto st396
		case 101:
			goto st396
		}
		goto tr105
	st396:
		if p++; p == pe {
			goto _test_eof396
		}
	st_case_396:
		switch data[p] {
		case 9:
			goto tr503
		case 32:
			goto tr503
		case 58:
			goto tr504
		}
		goto st0
tr87:
//line msg_parse.rl:55

			mark = p
		
	goto st397
	st397:
		if p++; p == pe {
			goto _test_eof397
		}
	st_case_397:
//line msg_parse.go:8169
		switch data[p] {
		case 9:
			goto tr505
		case 32:
			goto tr505
		case 58:
			goto tr506
		case 69:
			goto st398
		case 79:
			goto st453
		case 101:
			goto st398
		case 111:
			goto st453
		}
		goto tr105
	st398:
		if p++; p == pe {
			goto _test_eof398
		}
	st_case_398:
		switch data[p] {
		case 67:
			goto st399
		case 70:
			goto st409
		case 77:
			goto st420
		case 80:
			goto st433
		case 81:
			goto st439
		case 84:
			goto st444
		case 99:
			goto st399
		case 102:
			goto st409
		case 109:
			goto st420
		case 112:
			goto st433
		case 113:
			goto st439
		case 116:
			goto st444
		}
		goto tr105
	st399:
		if p++; p == pe {
			goto _test_eof399
		}
	st_case_399:
		switch data[p] {
		case 79:
			goto st400
		case 111:
			goto st400
		}
		goto tr105
	st400:
		if p++; p == pe {
			goto _test_eof400
		}
	st_case_400:
		switch data[p] {
		case 82:
			goto st401
		case 114:
			goto st401
		}
		goto tr105
	st401:
		if p++; p == pe {
			goto _test_eof401
		}
	st_case_401:
		switch data[p] {
		case 68:
			goto st402
		case 100:
			goto st402
		}
		goto tr105
	st402:
		if p++; p == pe {
			goto _test_eof402
		}
	st_case_402:
		if data[p] == 45 {
			goto st403
		}
		goto tr105
	st403:
		if p++; p == pe {
			goto _test_eof403
		}
	st_case_403:
		switch data[p] {
		case 82:
			goto st404
		case 114:
			goto st404
		}
		goto tr105
	st404:
		if p++; p == pe {
			goto _test_eof404
		}
	st_case_404:
		switch data[p] {
		case 79:
			goto st405
		case 111:
			goto st405
		}
		goto tr105
	st405:
		if p++; p == pe {
			goto _test_eof405
		}
	st_case_405:
		switch data[p] {
		case 85:
			goto st406
		case 117:
			goto st406
		}
		goto tr105
	st406:
		if p++; p == pe {
			goto _test_eof406
		}
	st_case_406:
		switch data[p] {
		case 84:
			goto st407
		case 116:
			goto st407
		}
		goto tr105
	st407:
		if p++; p == pe {
			goto _test_eof407
		}
	st_case_407:
		switch data[p] {
		case 69:
			goto st408
		case 101:
			goto st408
		}
		goto tr105
	st408:
		if p++; p == pe {
			goto _test_eof408
		}
	st_case_408:
		switch data[p] {
		case 9:
			goto tr524
		case 32:
			goto tr524
		case 58:
			goto tr525
		}
		goto st0
	st409:
		if p++; p == pe {
			goto _test_eof409
		}
	st_case_409:
		switch data[p] {
		case 69:
			goto st410
		case 101:
			goto st410
		}
		goto tr105
	st410:
		if p++; p == pe {
			goto _test_eof410
		}
	st_case_410:
		switch data[p] {
		case 82:
			goto st411
		case 114:
			goto st411
		}
		goto tr105
	st411:
		if p++; p == pe {
			goto _test_eof411
		}
	st_case_411:
		switch data[p] {
		case 45:
			goto st412
		case 82:
			goto st415
		case 114:
			goto st415
		}
		goto tr105
	st412:
		if p++; p == pe {
			goto _test_eof412
		}
	st_case_412:
		switch data[p] {
		case 84:
			goto st413
		case 116:
			goto st413
		}
		goto tr105
	st413:
		if p++; p == pe {
			goto _test_eof413
		}
	st_case_413:
		switch data[p] {
		case 79:
			goto st414
		case 111:
			goto st414
		}
		goto tr105
	st414:
		if p++; p == pe {
			goto _test_eof414
		}
	st_case_414:
		switch data[p] {
		case 9:
			goto tr505
		case 32:
			goto tr505
		case 58:
			goto tr506
		}
		goto st0
	st415:
		if p++; p == pe {
			goto _test_eof415
		}
	st_case_415:
		switch data[p] {
		case 69:
			goto st416
		case 101:
			goto st416
		}
		goto tr105
	st416:
		if p++; p == pe {
			goto _test_eof416
		}
	st_case_416:
		switch data[p] {
		case 68:
			goto st417
		case 100:
			goto st417
		}
		goto tr105
	st417:
		if p++; p == pe {
			goto _test_eof417
		}
	st_case_417:
		if data[p] == 45 {
			goto st418
		}
		goto tr105
	st418:
		if p++; p == pe {
			goto _test_eof418
		}
	st_case_418:
		switch data[p] {
		case 66:
			goto st419
		case 98:
			goto st419
		}
		goto tr105
	st419:
		if p++; p == pe {
			goto _test_eof419
		}
	st_case_419:
		switch data[p] {
		case 89:
			goto st134
		case 121:
			goto st134
		}
		goto tr105
	st420:
		if p++; p == pe {
			goto _test_eof420
		}
	st_case_420:
		switch data[p] {
		case 79:
			goto st421
		case 111:
			goto st421
		}
		goto tr105
	st421:
		if p++; p == pe {
			goto _test_eof421
		}
	st_case_421:
		switch data[p] {
		case 84:
			goto st422
		case 116:
			goto st422
		}
		goto tr105
	st422:
		if p++; p == pe {
			goto _test_eof422
		}
	st_case_422:
		switch data[p] {
		case 69:
			goto st423
		case 101:
			goto st423
		}
		goto tr105
	st423:
		if p++; p == pe {
			goto _test_eof423
		}
	st_case_423:
		if data[p] == 45 {
			goto st424
		}
		goto tr105
	st424:
		if p++; p == pe {
			goto _test_eof424
		}
	st_case_424:
		switch data[p] {
		case 80:
			goto st425
		case 112:
			goto st425
		}
		goto tr105
	st425:
		if p++; p == pe {
			goto _test_eof425
		}
	st_case_425:
		switch data[p] {
		case 65:
			goto st426
		case 97:
			goto st426
		}
		goto tr105
	st426:
		if p++; p == pe {
			goto _test_eof426
		}
	st_case_426:
		switch data[p] {
		case 82:
			goto st427
		case 114:
			goto st427
		}
		goto tr105
	st427:
		if p++; p == pe {
			goto _test_eof427
		}
	st_case_427:
		switch data[p] {
		case 84:
			goto st428
		case 116:
			goto st428
		}
		goto tr105
	st428:
		if p++; p == pe {
			goto _test_eof428
		}
	st_case_428:
		switch data[p] {
		case 89:
			goto st429
		case 121:
			goto st429
		}
		goto tr105
	st429:
		if p++; p == pe {
			goto _test_eof429
		}
	st_case_429:
		if data[p] == 45 {
			goto st430
		}
		goto tr105
	st430:
		if p++; p == pe {
			goto _test_eof430
		}
	st_case_430:
		switch data[p] {
		case 73:
			goto st431
		case 105:
			goto st431
		}
		goto tr105
	st431:
		if p++; p == pe {
			goto _test_eof431
		}
	st_case_431:
		switch data[p] {
		case 68:
			goto st432
		case 100:
			goto st432
		}
		goto tr105
	st432:
		if p++; p == pe {
			goto _test_eof432
		}
	st_case_432:
		switch data[p] {
		case 9:
			goto tr549
		case 32:
			goto tr549
		case 58:
			goto tr550
		}
		goto st0
	st433:
		if p++; p == pe {
			goto _test_eof433
		}
	st_case_433:
		switch data[p] {
		case 76:
			goto st434
		case 108:
			goto st434
		}
		goto tr105
	st434:
		if p++; p == pe {
			goto _test_eof434
		}
	st_case_434:
		switch data[p] {
		case 89:
			goto st435
		case 121:
			goto st435
		}
		goto tr105
	st435:
		if p++; p == pe {
			goto _test_eof435
		}
	st_case_435:
		if data[p] == 45 {
			goto st436
		}
		goto tr105
	st436:
		if p++; p == pe {
			goto _test_eof436
		}
	st_case_436:
		switch data[p] {
		case 84:
			goto st437
		case 116:
			goto st437
		}
		goto tr105
	st437:
		if p++; p == pe {
			goto _test_eof437
		}
	st_case_437:
		switch data[p] {
		case 79:
			goto st438
		case 111:
			goto st438
		}
		goto tr105
	st438:
		if p++; p == pe {
			goto _test_eof438
		}
	st_case_438:
		switch data[p] {
		case 9:
			goto tr556
		case 32:
			goto tr556
		case 58:
			goto tr557
		}
		goto st0
	st439:
		if p++; p == pe {
			goto _test_eof439
		}
	st_case_439:
		switch data[p] {
		case 85:
			goto st440
		case 117:
			goto st440
		}
		goto tr105
	st440:
		if p++; p == pe {
			goto _test_eof440
		}
	st_case_440:
		switch data[p] {
		case 73:
			goto st441
		case 105:
			goto st441
		}
		goto tr105
	st441:
		if p++; p == pe {
			goto _test_eof441
		}
	st_case_441:
		switch data[p] {
		case 82:
			goto st442
		case 114:
			goto st442
		}
		goto tr105
	st442:
		if p++; p == pe {
			goto _test_eof442
		}
	st_case_442:
		switch data[p] {
		case 69:
			goto st443
		case 101:
			goto st443
		}
		goto tr105
	st443:
		if p++; p == pe {
			goto _test_eof443
		}
	st_case_443:
		switch data[p] {
		case 9:
			goto tr562
		case 32:
			goto tr562
		case 58:
			goto tr563
		}
		goto st0
	st444:
		if p++; p == pe {
			goto _test_eof444
		}
	st_case_444:
		switch data[p] {
		case 82:
			goto st445
		case 114:
			goto st445
		}
		goto tr105
	st445:
		if p++; p == pe {
			goto _test_eof445
		}
	st_case_445:
		switch data[p] {
		case 89:
			goto st446
		case 121:
			goto st446
		}
		goto tr105
	st446:
		if p++; p == pe {
			goto _test_eof446
		}
	st_case_446:
		if data[p] == 45 {
			goto st447
		}
		goto tr105
	st447:
		if p++; p == pe {
			goto _test_eof447
		}
	st_case_447:
		switch data[p] {
		case 65:
			goto st448
		case 97:
			goto st448
		}
		goto tr105
	st448:
		if p++; p == pe {
			goto _test_eof448
		}
	st_case_448:
		switch data[p] {
		case 70:
			goto st449
		case 102:
			goto st449
		}
		goto tr105
	st449:
		if p++; p == pe {
			goto _test_eof449
		}
	st_case_449:
		switch data[p] {
		case 84:
			goto st450
		case 116:
			goto st450
		}
		goto tr105
	st450:
		if p++; p == pe {
			goto _test_eof450
		}
	st_case_450:
		switch data[p] {
		case 69:
			goto st451
		case 101:
			goto st451
		}
		goto tr105
	st451:
		if p++; p == pe {
			goto _test_eof451
		}
	st_case_451:
		switch data[p] {
		case 82:
			goto st452
		case 114:
			goto st452
		}
		goto tr105
	st452:
		if p++; p == pe {
			goto _test_eof452
		}
	st_case_452:
		switch data[p] {
		case 9:
			goto tr572
		case 32:
			goto tr572
		case 58:
			goto tr573
		}
		goto st0
	st453:
		if p++; p == pe {
			goto _test_eof453
		}
	st_case_453:
		switch data[p] {
		case 85:
			goto st454
		case 117:
			goto st454
		}
		goto tr105
	st454:
		if p++; p == pe {
			goto _test_eof454
		}
	st_case_454:
		switch data[p] {
		case 84:
			goto st455
		case 116:
			goto st455
		}
		goto tr105
	st455:
		if p++; p == pe {
			goto _test_eof455
		}
	st_case_455:
		switch data[p] {
		case 69:
			goto st456
		case 101:
			goto st456
		}
		goto tr105
	st456:
		if p++; p == pe {
			goto _test_eof456
		}
	st_case_456:
		switch data[p] {
		case 9:
			goto tr577
		case 32:
			goto tr577
		case 58:
			goto tr578
		}
		goto st0
tr88:
//line msg_parse.rl:55

			mark = p
		
	goto st457
	st457:
		if p++; p == pe {
			goto _test_eof457
		}
	st_case_457:
//line msg_parse.go:8924
		switch data[p] {
		case 9:
			goto tr579
		case 32:
			goto tr579
		case 58:
			goto tr580
		case 69:
			goto st458
		case 85:
			goto st463
		case 101:
			goto st458
		case 117:
			goto st463
		}
		goto st0
	st458:
		if p++; p == pe {
			goto _test_eof458
		}
	st_case_458:
		switch data[p] {
		case 82:
			goto st459
		case 114:
			goto st459
		}
		goto tr105
	st459:
		if p++; p == pe {
			goto _test_eof459
		}
	st_case_459:
		switch data[p] {
		case 86:
			goto st460
		case 118:
			goto st460
		}
		goto tr105
	st460:
		if p++; p == pe {
			goto _test_eof460
		}
	st_case_460:
		switch data[p] {
		case 69:
			goto st461
		case 101:
			goto st461
		}
		goto tr105
	st461:
		if p++; p == pe {
			goto _test_eof461
		}
	st_case_461:
		switch data[p] {
		case 82:
			goto st462
		case 114:
			goto st462
		}
		goto tr105
	st462:
		if p++; p == pe {
			goto _test_eof462
		}
	st_case_462:
		switch data[p] {
		case 9:
			goto tr587
		case 32:
			goto tr587
		case 58:
			goto tr588
		}
		goto st0
	st463:
		if p++; p == pe {
			goto _test_eof463
		}
	st_case_463:
		switch data[p] {
		case 66:
			goto st464
		case 80:
			goto st469
		case 98:
			goto st464
		case 112:
			goto st469
		}
		goto tr105
	st464:
		if p++; p == pe {
			goto _test_eof464
		}
	st_case_464:
		switch data[p] {
		case 74:
			goto st465
		case 106:
			goto st465
		}
		goto tr105
	st465:
		if p++; p == pe {
			goto _test_eof465
		}
	st_case_465:
		switch data[p] {
		case 69:
			goto st466
		case 101:
			goto st466
		}
		goto tr105
	st466:
		if p++; p == pe {
			goto _test_eof466
		}
	st_case_466:
		switch data[p] {
		case 67:
			goto st467
		case 99:
			goto st467
		}
		goto tr105
	st467:
		if p++; p == pe {
			goto _test_eof467
		}
	st_case_467:
		switch data[p] {
		case 84:
			goto st468
		case 116:
			goto st468
		}
		goto tr105
	st468:
		if p++; p == pe {
			goto _test_eof468
		}
	st_case_468:
		switch data[p] {
		case 9:
			goto tr579
		case 32:
			goto tr579
		case 58:
			goto tr580
		}
		goto st0
	st469:
		if p++; p == pe {
			goto _test_eof469
		}
	st_case_469:
		switch data[p] {
		case 80:
			goto st470
		case 112:
			goto st470
		}
		goto tr105
	st470:
		if p++; p == pe {
			goto _test_eof470
		}
	st_case_470:
		switch data[p] {
		case 79:
			goto st471
		case 111:
			goto st471
		}
		goto tr105
	st471:
		if p++; p == pe {
			goto _test_eof471
		}
	st_case_471:
		switch data[p] {
		case 82:
			goto st472
		case 114:
			goto st472
		}
		goto tr105
	st472:
		if p++; p == pe {
			goto _test_eof472
		}
	st_case_472:
		switch data[p] {
		case 84:
			goto st473
		case 116:
			goto st473
		}
		goto tr105
	st473:
		if p++; p == pe {
			goto _test_eof473
		}
	st_case_473:
		switch data[p] {
		case 69:
			goto st474
		case 101:
			goto st474
		}
		goto tr105
	st474:
		if p++; p == pe {
			goto _test_eof474
		}
	st_case_474:
		switch data[p] {
		case 68:
			goto st278
		case 100:
			goto st278
		}
		goto tr105
tr89:
//line msg_parse.rl:55

			mark = p
		
	goto st475
	st475:
		if p++; p == pe {
			goto _test_eof475
		}
	st_case_475:
//line msg_parse.go:9165
		switch data[p] {
		case 9:
			goto tr601
		case 32:
			goto tr601
		case 58:
			goto tr602
		case 73:
			goto st476
		case 79:
			goto st484
		case 105:
			goto st476
		case 111:
			goto st484
		}
		goto tr105
	st476:
		if p++; p == pe {
			goto _test_eof476
		}
	st_case_476:
		switch data[p] {
		case 77:
			goto st477
		case 109:
			goto st477
		}
		goto tr105
	st477:
		if p++; p == pe {
			goto _test_eof477
		}
	st_case_477:
		switch data[p] {
		case 69:
			goto st478
		case 101:
			goto st478
		}
		goto tr105
	st478:
		if p++; p == pe {
			goto _test_eof478
		}
	st_case_478:
		switch data[p] {
		case 83:
			goto st479
		case 115:
			goto st479
		}
		goto tr105
	st479:
		if p++; p == pe {
			goto _test_eof479
		}
	st_case_479:
		switch data[p] {
		case 84:
			goto st480
		case 116:
			goto st480
		}
		goto tr105
	st480:
		if p++; p == pe {
			goto _test_eof480
		}
	st_case_480:
		switch data[p] {
		case 65:
			goto st481
		case 97:
			goto st481
		}
		goto tr105
	st481:
		if p++; p == pe {
			goto _test_eof481
		}
	st_case_481:
		switch data[p] {
		case 77:
			goto st482
		case 109:
			goto st482
		}
		goto tr105
	st482:
		if p++; p == pe {
			goto _test_eof482
		}
	st_case_482:
		switch data[p] {
		case 80:
			goto st483
		case 112:
			goto st483
		}
		goto tr105
	st483:
		if p++; p == pe {
			goto _test_eof483
		}
	st_case_483:
		switch data[p] {
		case 9:
			goto tr612
		case 32:
			goto tr612
		case 58:
			goto tr613
		}
		goto st0
	st484:
		if p++; p == pe {
			goto _test_eof484
		}
	st_case_484:
		switch data[p] {
		case 9:
			goto tr601
		case 32:
			goto tr601
		case 58:
			goto tr602
		}
		goto st0
tr90:
//line msg_parse.rl:55

			mark = p
		
	goto st485
	st485:
		if p++; p == pe {
			goto _test_eof485
		}
	st_case_485:
//line msg_parse.go:9306
		switch data[p] {
		case 9:
			goto tr614
		case 32:
			goto tr614
		case 58:
			goto tr615
		case 78:
			goto st486
		case 83:
			goto st496
		case 110:
			goto st486
		case 115:
			goto st496
		}
		goto st0
	st486:
		if p++; p == pe {
			goto _test_eof486
		}
	st_case_486:
		switch data[p] {
		case 83:
			goto st487
		case 115:
			goto st487
		}
		goto tr105
	st487:
		if p++; p == pe {
			goto _test_eof487
		}
	st_case_487:
		switch data[p] {
		case 85:
			goto st488
		case 117:
			goto st488
		}
		goto tr105
	st488:
		if p++; p == pe {
			goto _test_eof488
		}
	st_case_488:
		switch data[p] {
		case 80:
			goto st489
		case 112:
			goto st489
		}
		goto tr105
	st489:
		if p++; p == pe {
			goto _test_eof489
		}
	st_case_489:
		switch data[p] {
		case 80:
			goto st490
		case 112:
			goto st490
		}
		goto tr105
	st490:
		if p++; p == pe {
			goto _test_eof490
		}
	st_case_490:
		switch data[p] {
		case 79:
			goto st491
		case 111:
			goto st491
		}
		goto tr105
	st491:
		if p++; p == pe {
			goto _test_eof491
		}
	st_case_491:
		switch data[p] {
		case 82:
			goto st492
		case 114:
			goto st492
		}
		goto tr105
	st492:
		if p++; p == pe {
			goto _test_eof492
		}
	st_case_492:
		switch data[p] {
		case 84:
			goto st493
		case 116:
			goto st493
		}
		goto tr105
	st493:
		if p++; p == pe {
			goto _test_eof493
		}
	st_case_493:
		switch data[p] {
		case 69:
			goto st494
		case 101:
			goto st494
		}
		goto tr105
	st494:
		if p++; p == pe {
			goto _test_eof494
		}
	st_case_494:
		switch data[p] {
		case 68:
			goto st495
		case 100:
			goto st495
		}
		goto tr105
	st495:
		if p++; p == pe {
			goto _test_eof495
		}
	st_case_495:
		switch data[p] {
		case 9:
			goto tr627
		case 32:
			goto tr627
		case 58:
			goto tr628
		}
		goto st0
	st496:
		if p++; p == pe {
			goto _test_eof496
		}
	st_case_496:
		switch data[p] {
		case 69:
			goto st497
		case 101:
			goto st497
		}
		goto tr105
	st497:
		if p++; p == pe {
			goto _test_eof497
		}
	st_case_497:
		switch data[p] {
		case 82:
			goto st498
		case 114:
			goto st498
		}
		goto tr105
	st498:
		if p++; p == pe {
			goto _test_eof498
		}
	st_case_498:
		if data[p] == 45 {
			goto st499
		}
		goto tr105
	st499:
		if p++; p == pe {
			goto _test_eof499
		}
	st_case_499:
		switch data[p] {
		case 65:
			goto st500
		case 97:
			goto st500
		}
		goto tr105
	st500:
		if p++; p == pe {
			goto _test_eof500
		}
	st_case_500:
		switch data[p] {
		case 71:
			goto st501
		case 103:
			goto st501
		}
		goto tr105
	st501:
		if p++; p == pe {
			goto _test_eof501
		}
	st_case_501:
		switch data[p] {
		case 69:
			goto st502
		case 101:
			goto st502
		}
		goto tr105
	st502:
		if p++; p == pe {
			goto _test_eof502
		}
	st_case_502:
		switch data[p] {
		case 78:
			goto st503
		case 110:
			goto st503
		}
		goto tr105
	st503:
		if p++; p == pe {
			goto _test_eof503
		}
	st_case_503:
		switch data[p] {
		case 84:
			goto st504
		case 116:
			goto st504
		}
		goto tr105
	st504:
		if p++; p == pe {
			goto _test_eof504
		}
	st_case_504:
		switch data[p] {
		case 9:
			goto tr637
		case 32:
			goto tr637
		case 58:
			goto tr638
		}
		goto st0
	st505:
		if p++; p == pe {
			goto _test_eof505
		}
	st_case_505:
		switch data[p] {
		case 9:
			goto st506
		case 32:
			goto st506
		case 58:
			goto st507
		case 73:
			goto st519
		case 105:
			goto st519
		}
		goto st0
	st506:
		if p++; p == pe {
			goto _test_eof506
		}
	st_case_506:
		switch data[p] {
		case 9:
			goto st506
		case 32:
			goto st506
		case 58:
			goto st507
		}
		goto st0
	st507:
		if p++; p == pe {
			goto _test_eof507
		}
	st_case_507:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st507
		case 32:
			goto st507
		case 269:
			goto tr648
		case 525:
			goto st516
		}
		switch {
		case _widec < 224:
			switch {
			case _widec > 127:
				if 192 <= _widec && _widec <= 223 {
					goto tr643
				}
			case _widec >= 33:
				goto tr642
			}
		case _widec > 239:
			switch {
			case _widec < 248:
				if 240 <= _widec && _widec <= 247 {
					goto tr645
				}
			case _widec > 251:
				if 252 <= _widec && _widec <= 253 {
					goto tr647
				}
			default:
				goto tr646
			}
		default:
			goto tr644
		}
		goto st0
tr642:
//line msg_parse.rl:55

			mark = p
		
	goto st508
	st508:
		if p++; p == pe {
			goto _test_eof508
		}
	st_case_508:
//line msg_parse.go:9645
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st508
		case 269:
			goto tr656
		case 525:
			goto st514
		}
		switch {
		case _widec < 224:
			switch {
			case _widec > 127:
				if 192 <= _widec && _widec <= 223 {
					goto st509
				}
			case _widec >= 32:
				goto st508
			}
		case _widec > 239:
			switch {
			case _widec < 248:
				if 240 <= _widec && _widec <= 247 {
					goto st511
				}
			case _widec > 251:
				if 252 <= _widec && _widec <= 253 {
					goto st513
				}
			default:
				goto st512
			}
		default:
			goto st510
		}
		goto st0
tr643:
//line msg_parse.rl:55

			mark = p
		
	goto st509
	st509:
		if p++; p == pe {
			goto _test_eof509
		}
	st_case_509:
//line msg_parse.go:9699
		if 128 <= data[p] && data[p] <= 191 {
			goto st508
		}
		goto st0
tr644:
//line msg_parse.rl:55

			mark = p
		
	goto st510
	st510:
		if p++; p == pe {
			goto _test_eof510
		}
	st_case_510:
//line msg_parse.go:9715
		if 128 <= data[p] && data[p] <= 191 {
			goto st509
		}
		goto st0
tr645:
//line msg_parse.rl:55

			mark = p
		
	goto st511
	st511:
		if p++; p == pe {
			goto _test_eof511
		}
	st_case_511:
//line msg_parse.go:9731
		if 128 <= data[p] && data[p] <= 191 {
			goto st510
		}
		goto st0
tr646:
//line msg_parse.rl:55

			mark = p
		
	goto st512
	st512:
		if p++; p == pe {
			goto _test_eof512
		}
	st_case_512:
//line msg_parse.go:9747
		if 128 <= data[p] && data[p] <= 191 {
			goto st511
		}
		goto st0
tr647:
//line msg_parse.rl:55

			mark = p
		
	goto st513
	st513:
		if p++; p == pe {
			goto _test_eof513
		}
	st_case_513:
//line msg_parse.go:9763
		if 128 <= data[p] && data[p] <= 191 {
			goto st512
		}
		goto st0
tr661:
//line msg_parse.rl:55

			mark = p
		
	goto st514
	st514:
		if p++; p == pe {
			goto _test_eof514
		}
	st_case_514:
//line msg_parse.go:9779
		if data[p] == 10 {
			goto tr658
		}
		goto st0
tr658:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st515
	st515:
		if p++; p == pe {
			goto _test_eof515
		}
	st_case_515:
//line msg_parse.go:9796
		switch data[p] {
		case 9:
			goto st508
		case 32:
			goto st508
		}
		goto st0
	st516:
		if p++; p == pe {
			goto _test_eof516
		}
	st_case_516:
		if data[p] == 10 {
			goto tr659
		}
		goto st0
tr659:
//line msg_parse.rl:50

			line++
			linep = p + 1
		
	goto st517
	st517:
		if p++; p == pe {
			goto _test_eof517
		}
	st_case_517:
//line msg_parse.go:9825
		switch data[p] {
		case 9:
			goto st518
		case 32:
			goto st518
		}
		goto st0
	st518:
		if p++; p == pe {
			goto _test_eof518
		}
	st_case_518:
		_widec = int16(data[p])
		if 13 <= data[p] && data[p] <= 13 {
			_widec = 256 + (int16(data[p]) - 0)
			if  lookAheadWSP(data, p, pe)  {
				_widec += 256
			}
		}
		switch _widec {
		case 9:
			goto st518
		case 32:
			goto st518
		case 269:
			goto tr648
		case 525:
			goto tr661
		}
		switch {
		case _widec < 224:
			switch {
			case _widec > 127:
				if 192 <= _widec && _widec <= 223 {
					goto tr643
				}
			case _widec >= 33:
				goto tr642
			}
		case _widec > 239:
			switch {
			case _widec < 248:
				if 240 <= _widec && _widec <= 247 {
					goto tr645
				}
			case _widec > 251:
				if 252 <= _widec && _widec <= 253 {
					goto tr647
				}
			default:
				goto tr646
			}
		default:
			goto tr644
		}
		goto st0
	st519:
		if p++; p == pe {
			goto _test_eof519
		}
	st_case_519:
		switch data[p] {
		case 65:
			goto st506
		case 97:
			goto st506
		}
		goto tr293
tr92:
//line msg_parse.rl:55

			mark = p
		
	goto st520
	st520:
		if p++; p == pe {
			goto _test_eof520
		}
	st_case_520:
//line msg_parse.go:9905
		switch data[p] {
		case 65:
			goto st521
		case 87:
			goto st527
		case 97:
			goto st521
		case 119:
			goto st527
		}
		goto tr105
	st521:
		if p++; p == pe {
			goto _test_eof521
		}
	st_case_521:
		switch data[p] {
		case 82:
			goto st522
		case 114:
			goto st522
		}
		goto tr105
	st522:
		if p++; p == pe {
			goto _test_eof522
		}
	st_case_522:
		switch data[p] {
		case 78:
			goto st523
		case 110:
			goto st523
		}
		goto tr105
	st523:
		if p++; p == pe {
			goto _test_eof523
		}
	st_case_523:
		switch data[p] {
		case 73:
			goto st524
		case 105:
			goto st524
		}
		goto tr105
	st524:
		if p++; p == pe {
			goto _test_eof524
		}
	st_case_524:
		switch data[p] {
		case 78:
			goto st525
		case 110:
			goto st525
		}
		goto tr105
	st525:
		if p++; p == pe {
			goto _test_eof525
		}
	st_case_525:
		switch data[p] {
		case 71:
			goto st526
		case 103:
			goto st526
		}
		goto tr105
	st526:
		if p++; p == pe {
			goto _test_eof526
		}
	st_case_526:
		switch data[p] {
		case 9:
			goto tr669
		case 32:
			goto tr669
		case 58:
			goto tr670
		}
		goto st0
	st527:
		if p++; p == pe {
			goto _test_eof527
		}
	st_case_527:
		switch data[p] {
		case 87:
			goto st528
		case 119:
			goto st528
		}
		goto tr105
	st528:
		if p++; p == pe {
			goto _test_eof528
		}
	st_case_528:
		if data[p] == 45 {
			goto st529
		}
		goto tr105
	st529:
		if p++; p == pe {
			goto _test_eof529
		}
	st_case_529:
		switch data[p] {
		case 65:
			goto st530
		case 97:
			goto st530
		}
		goto tr105
	st530:
		if p++; p == pe {
			goto _test_eof530
		}
	st_case_530:
		switch data[p] {
		case 85:
			goto st531
		case 117:
			goto st531
		}
		goto tr105
	st531:
		if p++; p == pe {
			goto _test_eof531
		}
	st_case_531:
		switch data[p] {
		case 84:
			goto st532
		case 116:
			goto st532
		}
		goto tr105
	st532:
		if p++; p == pe {
			goto _test_eof532
		}
	st_case_532:
		switch data[p] {
		case 72:
			goto st533
		case 104:
			goto st533
		}
		goto tr105
	st533:
		if p++; p == pe {
			goto _test_eof533
		}
	st_case_533:
		switch data[p] {
		case 69:
			goto st534
		case 101:
			goto st534
		}
		goto tr105
	st534:
		if p++; p == pe {
			goto _test_eof534
		}
	st_case_534:
		switch data[p] {
		case 78:
			goto st535
		case 110:
			goto st535
		}
		goto tr105
	st535:
		if p++; p == pe {
			goto _test_eof535
		}
	st_case_535:
		switch data[p] {
		case 84:
			goto st536
		case 116:
			goto st536
		}
		goto tr105
	st536:
		if p++; p == pe {
			goto _test_eof536
		}
	st_case_536:
		switch data[p] {
		case 73:
			goto st537
		case 105:
			goto st537
		}
		goto tr105
	st537:
		if p++; p == pe {
			goto _test_eof537
		}
	st_case_537:
		switch data[p] {
		case 67:
			goto st538
		case 99:
			goto st538
		}
		goto tr105
	st538:
		if p++; p == pe {
			goto _test_eof538
		}
	st_case_538:
		switch data[p] {
		case 65:
			goto st539
		case 97:
			goto st539
		}
		goto tr105
	st539:
		if p++; p == pe {
			goto _test_eof539
		}
	st_case_539:
		switch data[p] {
		case 84:
			goto st540
		case 116:
			goto st540
		}
		goto tr105
	st540:
		if p++; p == pe {
			goto _test_eof540
		}
	st_case_540:
		switch data[p] {
		case 69:
			goto st541
		case 101:
			goto st541
		}
		goto tr105
	st541:
		if p++; p == pe {
			goto _test_eof541
		}
	st_case_541:
		switch data[p] {
		case 9:
			goto tr685
		case 32:
			goto tr685
		case 58:
			goto tr686
		}
		goto st0
	st_out:
	_test_eof2: cs = 2; goto _test_eof
	_test_eof3: cs = 3; goto _test_eof
	_test_eof4: cs = 4; goto _test_eof
	_test_eof5: cs = 5; goto _test_eof
	_test_eof6: cs = 6; goto _test_eof
	_test_eof7: cs = 7; goto _test_eof
	_test_eof8: cs = 8; goto _test_eof
	_test_eof9: cs = 9; goto _test_eof
	_test_eof10: cs = 10; goto _test_eof
	_test_eof11: cs = 11; goto _test_eof
	_test_eof12: cs = 12; goto _test_eof
	_test_eof13: cs = 13; goto _test_eof
	_test_eof542: cs = 542; goto _test_eof
	_test_eof14: cs = 14; goto _test_eof
	_test_eof15: cs = 15; goto _test_eof
	_test_eof16: cs = 16; goto _test_eof
	_test_eof17: cs = 17; goto _test_eof
	_test_eof18: cs = 18; goto _test_eof
	_test_eof19: cs = 19; goto _test_eof
	_test_eof20: cs = 20; goto _test_eof
	_test_eof21: cs = 21; goto _test_eof
	_test_eof22: cs = 22; goto _test_eof
	_test_eof23: cs = 23; goto _test_eof
	_test_eof24: cs = 24; goto _test_eof
	_test_eof25: cs = 25; goto _test_eof
	_test_eof26: cs = 26; goto _test_eof
	_test_eof27: cs = 27; goto _test_eof
	_test_eof28: cs = 28; goto _test_eof
	_test_eof29: cs = 29; goto _test_eof
	_test_eof30: cs = 30; goto _test_eof
	_test_eof31: cs = 31; goto _test_eof
	_test_eof32: cs = 32; goto _test_eof
	_test_eof33: cs = 33; goto _test_eof
	_test_eof34: cs = 34; goto _test_eof
	_test_eof35: cs = 35; goto _test_eof
	_test_eof36: cs = 36; goto _test_eof
	_test_eof37: cs = 37; goto _test_eof
	_test_eof38: cs = 38; goto _test_eof
	_test_eof39: cs = 39; goto _test_eof
	_test_eof40: cs = 40; goto _test_eof
	_test_eof41: cs = 41; goto _test_eof
	_test_eof543: cs = 543; goto _test_eof
	_test_eof42: cs = 42; goto _test_eof
	_test_eof43: cs = 43; goto _test_eof
	_test_eof44: cs = 44; goto _test_eof
	_test_eof45: cs = 45; goto _test_eof
	_test_eof46: cs = 46; goto _test_eof
	_test_eof47: cs = 47; goto _test_eof
	_test_eof544: cs = 544; goto _test_eof
	_test_eof48: cs = 48; goto _test_eof
	_test_eof49: cs = 49; goto _test_eof
	_test_eof50: cs = 50; goto _test_eof
	_test_eof51: cs = 51; goto _test_eof
	_test_eof52: cs = 52; goto _test_eof
	_test_eof545: cs = 545; goto _test_eof
	_test_eof53: cs = 53; goto _test_eof
	_test_eof54: cs = 54; goto _test_eof
	_test_eof55: cs = 55; goto _test_eof
	_test_eof56: cs = 56; goto _test_eof
	_test_eof57: cs = 57; goto _test_eof
	_test_eof58: cs = 58; goto _test_eof
	_test_eof59: cs = 59; goto _test_eof
	_test_eof60: cs = 60; goto _test_eof
	_test_eof61: cs = 61; goto _test_eof
	_test_eof62: cs = 62; goto _test_eof
	_test_eof63: cs = 63; goto _test_eof
	_test_eof64: cs = 64; goto _test_eof
	_test_eof65: cs = 65; goto _test_eof
	_test_eof66: cs = 66; goto _test_eof
	_test_eof67: cs = 67; goto _test_eof
	_test_eof68: cs = 68; goto _test_eof
	_test_eof69: cs = 69; goto _test_eof
	_test_eof70: cs = 70; goto _test_eof
	_test_eof71: cs = 71; goto _test_eof
	_test_eof72: cs = 72; goto _test_eof
	_test_eof73: cs = 73; goto _test_eof
	_test_eof74: cs = 74; goto _test_eof
	_test_eof75: cs = 75; goto _test_eof
	_test_eof76: cs = 76; goto _test_eof
	_test_eof77: cs = 77; goto _test_eof
	_test_eof78: cs = 78; goto _test_eof
	_test_eof79: cs = 79; goto _test_eof
	_test_eof80: cs = 80; goto _test_eof
	_test_eof81: cs = 81; goto _test_eof
	_test_eof82: cs = 82; goto _test_eof
	_test_eof83: cs = 83; goto _test_eof
	_test_eof84: cs = 84; goto _test_eof
	_test_eof85: cs = 85; goto _test_eof
	_test_eof86: cs = 86; goto _test_eof
	_test_eof87: cs = 87; goto _test_eof
	_test_eof88: cs = 88; goto _test_eof
	_test_eof89: cs = 89; goto _test_eof
	_test_eof90: cs = 90; goto _test_eof
	_test_eof91: cs = 91; goto _test_eof
	_test_eof92: cs = 92; goto _test_eof
	_test_eof93: cs = 93; goto _test_eof
	_test_eof94: cs = 94; goto _test_eof
	_test_eof95: cs = 95; goto _test_eof
	_test_eof96: cs = 96; goto _test_eof
	_test_eof97: cs = 97; goto _test_eof
	_test_eof98: cs = 98; goto _test_eof
	_test_eof99: cs = 99; goto _test_eof
	_test_eof100: cs = 100; goto _test_eof
	_test_eof101: cs = 101; goto _test_eof
	_test_eof102: cs = 102; goto _test_eof
	_test_eof103: cs = 103; goto _test_eof
	_test_eof104: cs = 104; goto _test_eof
	_test_eof105: cs = 105; goto _test_eof
	_test_eof106: cs = 106; goto _test_eof
	_test_eof107: cs = 107; goto _test_eof
	_test_eof108: cs = 108; goto _test_eof
	_test_eof109: cs = 109; goto _test_eof
	_test_eof110: cs = 110; goto _test_eof
	_test_eof111: cs = 111; goto _test_eof
	_test_eof112: cs = 112; goto _test_eof
	_test_eof113: cs = 113; goto _test_eof
	_test_eof114: cs = 114; goto _test_eof
	_test_eof115: cs = 115; goto _test_eof
	_test_eof116: cs = 116; goto _test_eof
	_test_eof117: cs = 117; goto _test_eof
	_test_eof118: cs = 118; goto _test_eof
	_test_eof119: cs = 119; goto _test_eof
	_test_eof120: cs = 120; goto _test_eof
	_test_eof121: cs = 121; goto _test_eof
	_test_eof122: cs = 122; goto _test_eof
	_test_eof123: cs = 123; goto _test_eof
	_test_eof124: cs = 124; goto _test_eof
	_test_eof125: cs = 125; goto _test_eof
	_test_eof126: cs = 126; goto _test_eof
	_test_eof127: cs = 127; goto _test_eof
	_test_eof128: cs = 128; goto _test_eof
	_test_eof129: cs = 129; goto _test_eof
	_test_eof130: cs = 130; goto _test_eof
	_test_eof131: cs = 131; goto _test_eof
	_test_eof132: cs = 132; goto _test_eof
	_test_eof133: cs = 133; goto _test_eof
	_test_eof134: cs = 134; goto _test_eof
	_test_eof135: cs = 135; goto _test_eof
	_test_eof136: cs = 136; goto _test_eof
	_test_eof137: cs = 137; goto _test_eof
	_test_eof138: cs = 138; goto _test_eof
	_test_eof139: cs = 139; goto _test_eof
	_test_eof140: cs = 140; goto _test_eof
	_test_eof141: cs = 141; goto _test_eof
	_test_eof142: cs = 142; goto _test_eof
	_test_eof143: cs = 143; goto _test_eof
	_test_eof144: cs = 144; goto _test_eof
	_test_eof145: cs = 145; goto _test_eof
	_test_eof146: cs = 146; goto _test_eof
	_test_eof147: cs = 147; goto _test_eof
	_test_eof148: cs = 148; goto _test_eof
	_test_eof149: cs = 149; goto _test_eof
	_test_eof150: cs = 150; goto _test_eof
	_test_eof151: cs = 151; goto _test_eof
	_test_eof152: cs = 152; goto _test_eof
	_test_eof153: cs = 153; goto _test_eof
	_test_eof154: cs = 154; goto _test_eof
	_test_eof155: cs = 155; goto _test_eof
	_test_eof156: cs = 156; goto _test_eof
	_test_eof157: cs = 157; goto _test_eof
	_test_eof158: cs = 158; goto _test_eof
	_test_eof159: cs = 159; goto _test_eof
	_test_eof160: cs = 160; goto _test_eof
	_test_eof161: cs = 161; goto _test_eof
	_test_eof162: cs = 162; goto _test_eof
	_test_eof163: cs = 163; goto _test_eof
	_test_eof164: cs = 164; goto _test_eof
	_test_eof165: cs = 165; goto _test_eof
	_test_eof166: cs = 166; goto _test_eof
	_test_eof167: cs = 167; goto _test_eof
	_test_eof168: cs = 168; goto _test_eof
	_test_eof169: cs = 169; goto _test_eof
	_test_eof170: cs = 170; goto _test_eof
	_test_eof171: cs = 171; goto _test_eof
	_test_eof172: cs = 172; goto _test_eof
	_test_eof173: cs = 173; goto _test_eof
	_test_eof174: cs = 174; goto _test_eof
	_test_eof175: cs = 175; goto _test_eof
	_test_eof176: cs = 176; goto _test_eof
	_test_eof177: cs = 177; goto _test_eof
	_test_eof178: cs = 178; goto _test_eof
	_test_eof179: cs = 179; goto _test_eof
	_test_eof180: cs = 180; goto _test_eof
	_test_eof181: cs = 181; goto _test_eof
	_test_eof182: cs = 182; goto _test_eof
	_test_eof183: cs = 183; goto _test_eof
	_test_eof184: cs = 184; goto _test_eof
	_test_eof185: cs = 185; goto _test_eof
	_test_eof186: cs = 186; goto _test_eof
	_test_eof187: cs = 187; goto _test_eof
	_test_eof188: cs = 188; goto _test_eof
	_test_eof189: cs = 189; goto _test_eof
	_test_eof190: cs = 190; goto _test_eof
	_test_eof191: cs = 191; goto _test_eof
	_test_eof192: cs = 192; goto _test_eof
	_test_eof193: cs = 193; goto _test_eof
	_test_eof194: cs = 194; goto _test_eof
	_test_eof195: cs = 195; goto _test_eof
	_test_eof196: cs = 196; goto _test_eof
	_test_eof197: cs = 197; goto _test_eof
	_test_eof198: cs = 198; goto _test_eof
	_test_eof199: cs = 199; goto _test_eof
	_test_eof200: cs = 200; goto _test_eof
	_test_eof201: cs = 201; goto _test_eof
	_test_eof202: cs = 202; goto _test_eof
	_test_eof203: cs = 203; goto _test_eof
	_test_eof204: cs = 204; goto _test_eof
	_test_eof205: cs = 205; goto _test_eof
	_test_eof206: cs = 206; goto _test_eof
	_test_eof207: cs = 207; goto _test_eof
	_test_eof208: cs = 208; goto _test_eof
	_test_eof209: cs = 209; goto _test_eof
	_test_eof210: cs = 210; goto _test_eof
	_test_eof211: cs = 211; goto _test_eof
	_test_eof212: cs = 212; goto _test_eof
	_test_eof213: cs = 213; goto _test_eof
	_test_eof214: cs = 214; goto _test_eof
	_test_eof215: cs = 215; goto _test_eof
	_test_eof216: cs = 216; goto _test_eof
	_test_eof217: cs = 217; goto _test_eof
	_test_eof218: cs = 218; goto _test_eof
	_test_eof219: cs = 219; goto _test_eof
	_test_eof220: cs = 220; goto _test_eof
	_test_eof221: cs = 221; goto _test_eof
	_test_eof222: cs = 222; goto _test_eof
	_test_eof223: cs = 223; goto _test_eof
	_test_eof224: cs = 224; goto _test_eof
	_test_eof225: cs = 225; goto _test_eof
	_test_eof226: cs = 226; goto _test_eof
	_test_eof227: cs = 227; goto _test_eof
	_test_eof228: cs = 228; goto _test_eof
	_test_eof229: cs = 229; goto _test_eof
	_test_eof230: cs = 230; goto _test_eof
	_test_eof231: cs = 231; goto _test_eof
	_test_eof232: cs = 232; goto _test_eof
	_test_eof233: cs = 233; goto _test_eof
	_test_eof234: cs = 234; goto _test_eof
	_test_eof235: cs = 235; goto _test_eof
	_test_eof236: cs = 236; goto _test_eof
	_test_eof237: cs = 237; goto _test_eof
	_test_eof238: cs = 238; goto _test_eof
	_test_eof239: cs = 239; goto _test_eof
	_test_eof240: cs = 240; goto _test_eof
	_test_eof241: cs = 241; goto _test_eof
	_test_eof242: cs = 242; goto _test_eof
	_test_eof243: cs = 243; goto _test_eof
	_test_eof244: cs = 244; goto _test_eof
	_test_eof245: cs = 245; goto _test_eof
	_test_eof246: cs = 246; goto _test_eof
	_test_eof247: cs = 247; goto _test_eof
	_test_eof248: cs = 248; goto _test_eof
	_test_eof249: cs = 249; goto _test_eof
	_test_eof250: cs = 250; goto _test_eof
	_test_eof251: cs = 251; goto _test_eof
	_test_eof252: cs = 252; goto _test_eof
	_test_eof253: cs = 253; goto _test_eof
	_test_eof254: cs = 254; goto _test_eof
	_test_eof255: cs = 255; goto _test_eof
	_test_eof256: cs = 256; goto _test_eof
	_test_eof257: cs = 257; goto _test_eof
	_test_eof258: cs = 258; goto _test_eof
	_test_eof259: cs = 259; goto _test_eof
	_test_eof260: cs = 260; goto _test_eof
	_test_eof261: cs = 261; goto _test_eof
	_test_eof262: cs = 262; goto _test_eof
	_test_eof263: cs = 263; goto _test_eof
	_test_eof264: cs = 264; goto _test_eof
	_test_eof265: cs = 265; goto _test_eof
	_test_eof266: cs = 266; goto _test_eof
	_test_eof267: cs = 267; goto _test_eof
	_test_eof268: cs = 268; goto _test_eof
	_test_eof269: cs = 269; goto _test_eof
	_test_eof270: cs = 270; goto _test_eof
	_test_eof271: cs = 271; goto _test_eof
	_test_eof272: cs = 272; goto _test_eof
	_test_eof273: cs = 273; goto _test_eof
	_test_eof274: cs = 274; goto _test_eof
	_test_eof275: cs = 275; goto _test_eof
	_test_eof276: cs = 276; goto _test_eof
	_test_eof277: cs = 277; goto _test_eof
	_test_eof278: cs = 278; goto _test_eof
	_test_eof279: cs = 279; goto _test_eof
	_test_eof280: cs = 280; goto _test_eof
	_test_eof281: cs = 281; goto _test_eof
	_test_eof282: cs = 282; goto _test_eof
	_test_eof283: cs = 283; goto _test_eof
	_test_eof284: cs = 284; goto _test_eof
	_test_eof285: cs = 285; goto _test_eof
	_test_eof286: cs = 286; goto _test_eof
	_test_eof287: cs = 287; goto _test_eof
	_test_eof288: cs = 288; goto _test_eof
	_test_eof289: cs = 289; goto _test_eof
	_test_eof290: cs = 290; goto _test_eof
	_test_eof291: cs = 291; goto _test_eof
	_test_eof292: cs = 292; goto _test_eof
	_test_eof293: cs = 293; goto _test_eof
	_test_eof294: cs = 294; goto _test_eof
	_test_eof295: cs = 295; goto _test_eof
	_test_eof296: cs = 296; goto _test_eof
	_test_eof297: cs = 297; goto _test_eof
	_test_eof298: cs = 298; goto _test_eof
	_test_eof299: cs = 299; goto _test_eof
	_test_eof300: cs = 300; goto _test_eof
	_test_eof301: cs = 301; goto _test_eof
	_test_eof302: cs = 302; goto _test_eof
	_test_eof303: cs = 303; goto _test_eof
	_test_eof304: cs = 304; goto _test_eof
	_test_eof305: cs = 305; goto _test_eof
	_test_eof306: cs = 306; goto _test_eof
	_test_eof307: cs = 307; goto _test_eof
	_test_eof308: cs = 308; goto _test_eof
	_test_eof309: cs = 309; goto _test_eof
	_test_eof310: cs = 310; goto _test_eof
	_test_eof311: cs = 311; goto _test_eof
	_test_eof312: cs = 312; goto _test_eof
	_test_eof313: cs = 313; goto _test_eof
	_test_eof314: cs = 314; goto _test_eof
	_test_eof315: cs = 315; goto _test_eof
	_test_eof316: cs = 316; goto _test_eof
	_test_eof317: cs = 317; goto _test_eof
	_test_eof318: cs = 318; goto _test_eof
	_test_eof319: cs = 319; goto _test_eof
	_test_eof320: cs = 320; goto _test_eof
	_test_eof321: cs = 321; goto _test_eof
	_test_eof322: cs = 322; goto _test_eof
	_test_eof323: cs = 323; goto _test_eof
	_test_eof324: cs = 324; goto _test_eof
	_test_eof325: cs = 325; goto _test_eof
	_test_eof326: cs = 326; goto _test_eof
	_test_eof327: cs = 327; goto _test_eof
	_test_eof328: cs = 328; goto _test_eof
	_test_eof329: cs = 329; goto _test_eof
	_test_eof330: cs = 330; goto _test_eof
	_test_eof331: cs = 331; goto _test_eof
	_test_eof332: cs = 332; goto _test_eof
	_test_eof333: cs = 333; goto _test_eof
	_test_eof334: cs = 334; goto _test_eof
	_test_eof335: cs = 335; goto _test_eof
	_test_eof336: cs = 336; goto _test_eof
	_test_eof337: cs = 337; goto _test_eof
	_test_eof338: cs = 338; goto _test_eof
	_test_eof339: cs = 339; goto _test_eof
	_test_eof340: cs = 340; goto _test_eof
	_test_eof341: cs = 341; goto _test_eof
	_test_eof342: cs = 342; goto _test_eof
	_test_eof343: cs = 343; goto _test_eof
	_test_eof344: cs = 344; goto _test_eof
	_test_eof345: cs = 345; goto _test_eof
	_test_eof346: cs = 346; goto _test_eof
	_test_eof347: cs = 347; goto _test_eof
	_test_eof348: cs = 348; goto _test_eof
	_test_eof349: cs = 349; goto _test_eof
	_test_eof350: cs = 350; goto _test_eof
	_test_eof351: cs = 351; goto _test_eof
	_test_eof352: cs = 352; goto _test_eof
	_test_eof353: cs = 353; goto _test_eof
	_test_eof354: cs = 354; goto _test_eof
	_test_eof355: cs = 355; goto _test_eof
	_test_eof356: cs = 356; goto _test_eof
	_test_eof357: cs = 357; goto _test_eof
	_test_eof358: cs = 358; goto _test_eof
	_test_eof359: cs = 359; goto _test_eof
	_test_eof360: cs = 360; goto _test_eof
	_test_eof361: cs = 361; goto _test_eof
	_test_eof362: cs = 362; goto _test_eof
	_test_eof363: cs = 363; goto _test_eof
	_test_eof364: cs = 364; goto _test_eof
	_test_eof365: cs = 365; goto _test_eof
	_test_eof366: cs = 366; goto _test_eof
	_test_eof367: cs = 367; goto _test_eof
	_test_eof368: cs = 368; goto _test_eof
	_test_eof369: cs = 369; goto _test_eof
	_test_eof370: cs = 370; goto _test_eof
	_test_eof371: cs = 371; goto _test_eof
	_test_eof372: cs = 372; goto _test_eof
	_test_eof373: cs = 373; goto _test_eof
	_test_eof374: cs = 374; goto _test_eof
	_test_eof375: cs = 375; goto _test_eof
	_test_eof376: cs = 376; goto _test_eof
	_test_eof377: cs = 377; goto _test_eof
	_test_eof378: cs = 378; goto _test_eof
	_test_eof379: cs = 379; goto _test_eof
	_test_eof380: cs = 380; goto _test_eof
	_test_eof381: cs = 381; goto _test_eof
	_test_eof382: cs = 382; goto _test_eof
	_test_eof383: cs = 383; goto _test_eof
	_test_eof384: cs = 384; goto _test_eof
	_test_eof385: cs = 385; goto _test_eof
	_test_eof386: cs = 386; goto _test_eof
	_test_eof387: cs = 387; goto _test_eof
	_test_eof388: cs = 388; goto _test_eof
	_test_eof389: cs = 389; goto _test_eof
	_test_eof390: cs = 390; goto _test_eof
	_test_eof391: cs = 391; goto _test_eof
	_test_eof392: cs = 392; goto _test_eof
	_test_eof393: cs = 393; goto _test_eof
	_test_eof394: cs = 394; goto _test_eof
	_test_eof395: cs = 395; goto _test_eof
	_test_eof396: cs = 396; goto _test_eof
	_test_eof397: cs = 397; goto _test_eof
	_test_eof398: cs = 398; goto _test_eof
	_test_eof399: cs = 399; goto _test_eof
	_test_eof400: cs = 400; goto _test_eof
	_test_eof401: cs = 401; goto _test_eof
	_test_eof402: cs = 402; goto _test_eof
	_test_eof403: cs = 403; goto _test_eof
	_test_eof404: cs = 404; goto _test_eof
	_test_eof405: cs = 405; goto _test_eof
	_test_eof406: cs = 406; goto _test_eof
	_test_eof407: cs = 407; goto _test_eof
	_test_eof408: cs = 408; goto _test_eof
	_test_eof409: cs = 409; goto _test_eof
	_test_eof410: cs = 410; goto _test_eof
	_test_eof411: cs = 411; goto _test_eof
	_test_eof412: cs = 412; goto _test_eof
	_test_eof413: cs = 413; goto _test_eof
	_test_eof414: cs = 414; goto _test_eof
	_test_eof415: cs = 415; goto _test_eof
	_test_eof416: cs = 416; goto _test_eof
	_test_eof417: cs = 417; goto _test_eof
	_test_eof418: cs = 418; goto _test_eof
	_test_eof419: cs = 419; goto _test_eof
	_test_eof420: cs = 420; goto _test_eof
	_test_eof421: cs = 421; goto _test_eof
	_test_eof422: cs = 422; goto _test_eof
	_test_eof423: cs = 423; goto _test_eof
	_test_eof424: cs = 424; goto _test_eof
	_test_eof425: cs = 425; goto _test_eof
	_test_eof426: cs = 426; goto _test_eof
	_test_eof427: cs = 427; goto _test_eof
	_test_eof428: cs = 428; goto _test_eof
	_test_eof429: cs = 429; goto _test_eof
	_test_eof430: cs = 430; goto _test_eof
	_test_eof431: cs = 431; goto _test_eof
	_test_eof432: cs = 432; goto _test_eof
	_test_eof433: cs = 433; goto _test_eof
	_test_eof434: cs = 434; goto _test_eof
	_test_eof435: cs = 435; goto _test_eof
	_test_eof436: cs = 436; goto _test_eof
	_test_eof437: cs = 437; goto _test_eof
	_test_eof438: cs = 438; goto _test_eof
	_test_eof439: cs = 439; goto _test_eof
	_test_eof440: cs = 440; goto _test_eof
	_test_eof441: cs = 441; goto _test_eof
	_test_eof442: cs = 442; goto _test_eof
	_test_eof443: cs = 443; goto _test_eof
	_test_eof444: cs = 444; goto _test_eof
	_test_eof445: cs = 445; goto _test_eof
	_test_eof446: cs = 446; goto _test_eof
	_test_eof447: cs = 447; goto _test_eof
	_test_eof448: cs = 448; goto _test_eof
	_test_eof449: cs = 449; goto _test_eof
	_test_eof450: cs = 450; goto _test_eof
	_test_eof451: cs = 451; goto _test_eof
	_test_eof452: cs = 452; goto _test_eof
	_test_eof453: cs = 453; goto _test_eof
	_test_eof454: cs = 454; goto _test_eof
	_test_eof455: cs = 455; goto _test_eof
	_test_eof456: cs = 456; goto _test_eof
	_test_eof457: cs = 457; goto _test_eof
	_test_eof458: cs = 458; goto _test_eof
	_test_eof459: cs = 459; goto _test_eof
	_test_eof460: cs = 460; goto _test_eof
	_test_eof461: cs = 461; goto _test_eof
	_test_eof462: cs = 462; goto _test_eof
	_test_eof463: cs = 463; goto _test_eof
	_test_eof464: cs = 464; goto _test_eof
	_test_eof465: cs = 465; goto _test_eof
	_test_eof466: cs = 466; goto _test_eof
	_test_eof467: cs = 467; goto _test_eof
	_test_eof468: cs = 468; goto _test_eof
	_test_eof469: cs = 469; goto _test_eof
	_test_eof470: cs = 470; goto _test_eof
	_test_eof471: cs = 471; goto _test_eof
	_test_eof472: cs = 472; goto _test_eof
	_test_eof473: cs = 473; goto _test_eof
	_test_eof474: cs = 474; goto _test_eof
	_test_eof475: cs = 475; goto _test_eof
	_test_eof476: cs = 476; goto _test_eof
	_test_eof477: cs = 477; goto _test_eof
	_test_eof478: cs = 478; goto _test_eof
	_test_eof479: cs = 479; goto _test_eof
	_test_eof480: cs = 480; goto _test_eof
	_test_eof481: cs = 481; goto _test_eof
	_test_eof482: cs = 482; goto _test_eof
	_test_eof483: cs = 483; goto _test_eof
	_test_eof484: cs = 484; goto _test_eof
	_test_eof485: cs = 485; goto _test_eof
	_test_eof486: cs = 486; goto _test_eof
	_test_eof487: cs = 487; goto _test_eof
	_test_eof488: cs = 488; goto _test_eof
	_test_eof489: cs = 489; goto _test_eof
	_test_eof490: cs = 490; goto _test_eof
	_test_eof491: cs = 491; goto _test_eof
	_test_eof492: cs = 492; goto _test_eof
	_test_eof493: cs = 493; goto _test_eof
	_test_eof494: cs = 494; goto _test_eof
	_test_eof495: cs = 495; goto _test_eof
	_test_eof496: cs = 496; goto _test_eof
	_test_eof497: cs = 497; goto _test_eof
	_test_eof498: cs = 498; goto _test_eof
	_test_eof499: cs = 499; goto _test_eof
	_test_eof500: cs = 500; goto _test_eof
	_test_eof501: cs = 501; goto _test_eof
	_test_eof502: cs = 502; goto _test_eof
	_test_eof503: cs = 503; goto _test_eof
	_test_eof504: cs = 504; goto _test_eof
	_test_eof505: cs = 505; goto _test_eof
	_test_eof506: cs = 506; goto _test_eof
	_test_eof507: cs = 507; goto _test_eof
	_test_eof508: cs = 508; goto _test_eof
	_test_eof509: cs = 509; goto _test_eof
	_test_eof510: cs = 510; goto _test_eof
	_test_eof511: cs = 511; goto _test_eof
	_test_eof512: cs = 512; goto _test_eof
	_test_eof513: cs = 513; goto _test_eof
	_test_eof514: cs = 514; goto _test_eof
	_test_eof515: cs = 515; goto _test_eof
	_test_eof516: cs = 516; goto _test_eof
	_test_eof517: cs = 517; goto _test_eof
	_test_eof518: cs = 518; goto _test_eof
	_test_eof519: cs = 519; goto _test_eof
	_test_eof520: cs = 520; goto _test_eof
	_test_eof521: cs = 521; goto _test_eof
	_test_eof522: cs = 522; goto _test_eof
	_test_eof523: cs = 523; goto _test_eof
	_test_eof524: cs = 524; goto _test_eof
	_test_eof525: cs = 525; goto _test_eof
	_test_eof526: cs = 526; goto _test_eof
	_test_eof527: cs = 527; goto _test_eof
	_test_eof528: cs = 528; goto _test_eof
	_test_eof529: cs = 529; goto _test_eof
	_test_eof530: cs = 530; goto _test_eof
	_test_eof531: cs = 531; goto _test_eof
	_test_eof532: cs = 532; goto _test_eof
	_test_eof533: cs = 533; goto _test_eof
	_test_eof534: cs = 534; goto _test_eof
	_test_eof535: cs = 535; goto _test_eof
	_test_eof536: cs = 536; goto _test_eof
	_test_eof537: cs = 537; goto _test_eof
	_test_eof538: cs = 538; goto _test_eof
	_test_eof539: cs = 539; goto _test_eof
	_test_eof540: cs = 540; goto _test_eof
	_test_eof541: cs = 541; goto _test_eof

	_test_eof: {}
	if p == eof {
		switch cs {
		case 59, 60, 61, 62, 64, 65, 66, 67, 68, 69, 70, 72, 73, 74, 75, 76, 77, 78, 80, 81, 82, 83, 84, 85, 86, 88, 89, 90, 91, 92, 93, 94, 95, 97, 98, 100, 101, 102, 103, 104, 105, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 125, 126, 127, 128, 129, 130, 131, 132, 163, 164, 169, 170, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 192, 193, 194, 195, 196, 197, 198, 201, 202, 203, 204, 205, 206, 234, 235, 236, 239, 240, 241, 242, 243, 244, 245, 246, 248, 249, 250, 264, 265, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 303, 304, 305, 306, 307, 308, 309, 310, 311, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 358, 359, 360, 361, 362, 363, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 381, 382, 383, 384, 385, 386, 387, 388, 390, 391, 392, 393, 394, 395, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 409, 410, 411, 412, 413, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 433, 434, 435, 436, 437, 439, 440, 441, 442, 444, 445, 446, 447, 448, 449, 450, 451, 453, 454, 455, 458, 459, 460, 461, 463, 464, 465, 466, 467, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 486, 487, 488, 489, 490, 491, 492, 493, 494, 496, 497, 498, 499, 500, 501, 502, 503, 520, 521, 522, 523, 524, 525, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540:
//line msg_parse.rl:125

			p--

			{goto st44 }
		
		case 208, 209, 210, 211, 218, 219, 220, 221, 222, 238, 252, 253, 254, 255, 256, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 313, 314, 315, 316, 317, 318, 319, 320, 519:
//line msg_parse.rl:131

			p--

			{goto st44 }
		
		case 51, 135, 150, 151, 152, 153, 154, 166, 167, 168, 177, 178, 179, 180, 200, 285, 302:
//line msg_parse.rl:131

			p--

			{goto st44 }
		
//line msg_parse.rl:125

			p--

			{goto st44 }
		
//line msg_parse.go:10746
		}
	}

	_out: {}
	}

//line msg_parse.rl:365


	if cs < msg_first_final {
		if p == pe {
			return nil, errors.New(fmt.Sprintf("Incomplete SIP message: %s", data))
		} else {
			return nil, errors.New(fmt.Sprintf("Error in SIP message at line %d offset %d:\n%s", line, p - linep, data))
		}
	}

	if clen > 0 {
		if clen != len(data) - p {
			return nil, errors.New(fmt.Sprintf("Content-Length incorrect: %d != %d", clen, len(data) - p))
		}
		if ctype == sdp.ContentType {
			ms, err := sdp.Parse(string(data[p:len(data)]))
			if err != nil { return nil, err }
			msg.Payload = ms
		} else {
			msg.Payload = &MiscPayload{T: ctype, D: data[p:len(data)]}
		}
	}

	return msg, nil
}

func lookAheadWSP(data []byte, p, pe int) bool {
	return p + 2 < pe && (data[p+2] == ' ' || data[p+2] == '\t')
}