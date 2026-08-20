use pooler_protocol::{
    decode_binary_media, decode_multipart_media, encode_binary_media, encode_multipart_media,
    ContentPart, MediaCodecError, MediaLimits, MediaSource, MultipartMediaPart,
};

fn limits() -> MediaLimits {
    MediaLimits {
        max_body_bytes: 64 * 1024,
        max_part_bytes: 8 * 1024,
        max_parts: 8,
        max_header_bytes: 1024,
        max_headers_per_part: 4,
    }
}

#[test]
fn raw_binary_uses_existing_image_audio_and_file_semantics() {
    let image = decode_binary_media(b"png", "image/png", None, limits()).expect("decode image");
    assert_eq!(
        image,
        ContentPart::image("image/png", MediaSource::inline(b"png".to_vec()))
    );

    let audio = decode_binary_media(b"wav", "audio/wav", None, limits()).expect("decode audio");
    assert_eq!(
        audio,
        ContentPart::audio("audio/wav", MediaSource::inline(b"wav".to_vec()))
    );

    let file = decode_binary_media(b"pdf", "application/pdf", Some("paper.pdf"), limits())
        .expect("decode file");
    assert_eq!(
        file,
        ContentPart::file(
            Some("paper.pdf".to_owned()),
            "application/pdf",
            MediaSource::inline(b"pdf".to_vec()),
        )
    );

    let encoded = encode_binary_media(&file, limits()).expect("encode file");
    assert_eq!(encoded.body, b"pdf");
    assert_eq!(encoded.media_type, "application/pdf");
    assert_eq!(encoded.filename.as_deref(), Some("paper.pdf"));

    let image_file = decode_binary_media(b"png", "image/png", Some("cover.png"), limits())
        .expect("decode named image file");
    assert_eq!(
        image_file,
        ContentPart::file(
            Some("cover.png".to_owned()),
            "image/png",
            MediaSource::inline(b"png".to_vec()),
        )
    );
    assert_eq!(
        encode_binary_media(&image_file, limits())
            .expect("encode named image file")
            .filename
            .as_deref(),
        Some("cover.png")
    );
}

#[test]
fn multipart_round_trip_preserves_order_names_filenames_and_bytes() {
    let parts = vec![
        MultipartMediaPart::text("model", "whisper-1"),
        MultipartMediaPart::media(
            "cover",
            None,
            ContentPart::image("image/png", MediaSource::inline([1, 2, 3])),
        ),
        MultipartMediaPart::media(
            "recording",
            None,
            ContentPart::audio("audio/wav", MediaSource::inline([4, 5, 6])),
        ),
        MultipartMediaPart::media(
            "image_file",
            Some("cover.png".to_owned()),
            ContentPart::file(
                Some("cover.png".to_owned()),
                "image/png",
                MediaSource::inline([10, 11, 12]),
            ),
        ),
        MultipartMediaPart::media(
            "document",
            Some("paper.pdf".to_owned()),
            ContentPart::file(
                Some("paper.pdf".to_owned()),
                "application/pdf",
                MediaSource::inline([7, 8, 9]),
            ),
        ),
    ];
    let encoded = encode_multipart_media(&parts, "pooler-boundary", limits())
        .expect("encode multipart media");
    assert_eq!(
        encoded.content_type,
        "multipart/form-data; boundary=\"pooler-boundary\""
    );

    let decoded = decode_multipart_media(&encoded.body, &encoded.content_type, limits())
        .expect("decode multipart media");
    assert_eq!(decoded.parts, parts);
}

#[test]
fn quoted_names_and_quoted_boundaries_round_trip() {
    let parts = vec![MultipartMediaPart::text("prompt\"kind", "watercolor")];
    let encoded =
        encode_multipart_media(&parts, "pooler=quoted", limits()).expect("encode quoted name");
    assert_eq!(
        encoded.content_type,
        "multipart/form-data; boundary=\"pooler=quoted\""
    );
    let decoded = decode_multipart_media(&encoded.body, &encoded.content_type, limits())
        .expect("decode quoted boundary");
    assert_eq!(decoded.parts, parts);
}

#[test]
fn explicitly_typed_text_field_remains_semantic_text() {
    let body = b"--b\r\nContent-Disposition: form-data; name=\"prompt\"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n--b--\r\n";
    let decoded = decode_multipart_media(body, "multipart/form-data; boundary=b", limits())
        .expect("decode typed text");
    let expected = vec![MultipartMediaPart::text("prompt", "hello")];
    assert_eq!(decoded.parts, expected);

    let encoded = encode_multipart_media(&decoded.parts, "typed-text", limits())
        .expect("encode semantic text");
    assert_eq!(
        decode_multipart_media(&encoded.body, &encoded.content_type, limits())
            .expect("round-trip semantic text")
            .parts,
        expected
    );

    let mut invalid = b"--b\r\nContent-Disposition: form-data; name=\"prompt\"\r\nContent-Type: text/plain\r\n\r\n".to_vec();
    invalid.push(0xff);
    invalid.extend_from_slice(b"\r\n--b--\r\n");
    assert_eq!(
        decode_multipart_media(&invalid, "multipart/form-data; boundary=b", limits()),
        Err(MediaCodecError::InvalidText { part: 0 })
    );
}

#[test]
fn decode_rejects_duplicate_field_names_headers_and_parameters() {
    let duplicate_fields = b"--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\na\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nb\r\n--b--\r\n";
    assert_eq!(
        decode_multipart_media(
            duplicate_fields,
            "multipart/form-data; boundary=b",
            limits()
        ),
        Err(MediaCodecError::DuplicateFieldName {
            name: "file".to_owned()
        })
    );

    let duplicate_content_type = b"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\nContent-Type: image/png\r\ncontent-type: audio/wav\r\n\r\na\r\n--b--\r\n";
    assert_eq!(
        decode_multipart_media(
            duplicate_content_type,
            "multipart/form-data; boundary=b",
            limits()
        ),
        Err(MediaCodecError::DuplicateHeader {
            part: 0,
            header: "content-type".to_owned()
        })
    );

    let duplicate_name_parameter =
        b"--b\r\nContent-Disposition: form-data; name=\"a\"; NAME=\"b\"\r\n\r\na\r\n--b--\r\n";
    assert_eq!(
        decode_multipart_media(
            duplicate_name_parameter,
            "multipart/form-data; boundary=b",
            limits()
        ),
        Err(MediaCodecError::DuplicateDispositionParameter {
            part: 0,
            parameter: "name".to_owned()
        })
    );

    assert_eq!(
        decode_multipart_media(
            b"--a--\r\n",
            "multipart/form-data; boundary=a; BOUNDARY=b",
            limits()
        ),
        Err(MediaCodecError::InvalidContentType)
    );
    assert_eq!(
        decode_multipart_media(
            b"--a--\r\n",
            "multipart/form-data; boundary=a; charset=utf-8",
            limits()
        ),
        Err(MediaCodecError::InvalidContentType)
    );
}

#[test]
fn body_part_count_and_header_limits_are_enforced() {
    let media = MultipartMediaPart::media(
        "file",
        Some("a.bin".to_owned()),
        ContentPart::file(
            Some("a.bin".to_owned()),
            "application/octet-stream",
            MediaSource::inline([1, 2, 3]),
        ),
    );
    let encoded = encode_multipart_media(&[media], "b", limits()).expect("encode fixture");

    let mut body_limited = limits();
    body_limited.max_body_bytes = encoded.body.len() - 1;
    assert!(matches!(
        decode_multipart_media(&encoded.body, &encoded.content_type, body_limited),
        Err(MediaCodecError::BodyTooLarge { .. })
    ));

    let mut part_limited = limits();
    part_limited.max_part_bytes = 2;
    assert_eq!(
        decode_multipart_media(&encoded.body, &encoded.content_type, part_limited),
        Err(MediaCodecError::PartTooLarge {
            part: 0,
            limit: 2,
            observed: 3
        })
    );

    let two_parts = vec![
        MultipartMediaPart::text("first", "a"),
        MultipartMediaPart::text("second", "b"),
    ];
    let encoded_two = encode_multipart_media(&two_parts, "b", limits()).expect("encode fields");
    let mut count_limited = limits();
    count_limited.max_parts = 1;
    assert_eq!(
        decode_multipart_media(&encoded_two.body, &encoded_two.content_type, count_limited),
        Err(MediaCodecError::TooManyParts { limit: 1 })
    );

    let mut header_bytes_limited = limits();
    header_bytes_limited.max_header_bytes = 33;
    assert_eq!(
        decode_multipart_media(&encoded.body, &encoded.content_type, header_bytes_limited),
        Err(MediaCodecError::HeadersTooLarge { part: 0, limit: 33 })
    );

    let mut header_count_limited = limits();
    header_count_limited.max_headers_per_part = 1;
    assert_eq!(
        decode_multipart_media(&encoded.body, &encoded.content_type, header_count_limited),
        Err(MediaCodecError::TooManyHeaders { part: 0, limit: 1 })
    );

    let mut encode_header_limited = limits();
    encode_header_limited.max_header_bytes = 40;
    assert_eq!(
        encode_multipart_media(
            &[MultipartMediaPart::text("long-field-name", "value")],
            "b",
            encode_header_limited
        ),
        Err(MediaCodecError::HeadersTooLarge { part: 0, limit: 40 })
    );

    let mut encode_header_count_limited = limits();
    encode_header_count_limited.max_headers_per_part = 0;
    assert_eq!(
        encode_multipart_media(
            &[MultipartMediaPart::text("field", "value")],
            "b",
            encode_header_count_limited
        ),
        Err(MediaCodecError::TooManyHeaders { part: 0, limit: 0 })
    );

    let mut outer_header_limited = limits();
    outer_header_limited.max_header_bytes = 24;
    assert!(matches!(
        encode_multipart_media(&[], "pooler=quoted", outer_header_limited),
        Err(MediaCodecError::HeaderValueTooLarge { .. })
    ));
}

#[test]
fn raw_and_encoded_bodies_enforce_total_limits() {
    let mut bounded = limits();
    bounded.max_body_bytes = 2;
    assert_eq!(
        decode_binary_media(b"abc", "image/png", None, bounded),
        Err(MediaCodecError::BodyTooLarge {
            limit: 2,
            observed: 3
        })
    );
    assert!(matches!(
        encode_multipart_media(&[MultipartMediaPart::text("prompt", "abc")], "b", bounded),
        Err(MediaCodecError::BodyTooLarge { .. })
    ));

    let mut header_limited = limits();
    header_limited.max_header_bytes = 8;
    assert_eq!(
        decode_binary_media(b"x", "image/png", None, header_limited),
        Err(MediaCodecError::HeaderValueTooLarge {
            limit: 8,
            observed: 9
        })
    );
}

#[test]
fn codecs_reject_ambiguous_or_unrepresentable_inputs() {
    assert_eq!(
        decode_binary_media(b"x", "image/png, audio/wav", None, limits()),
        Err(MediaCodecError::InvalidContentType)
    );
    assert_eq!(
        encode_binary_media(
            &ContentPart::audio(
                "audio/wav",
                MediaSource::uri("https://example.test/audio.wav")
            ),
            limits()
        ),
        Err(MediaCodecError::NonInlineSource)
    );
    assert_eq!(
        encode_binary_media(
            &ContentPart::image(
                "application/octet-stream",
                MediaSource::inline(b"not-an-image".to_vec())
            ),
            limits()
        ),
        Err(MediaCodecError::MediaTypeMismatch)
    );

    let conflicting = MultipartMediaPart::media(
        "file",
        Some("wrapper.txt".to_owned()),
        ContentPart::file(
            Some("semantic.txt".to_owned()),
            "text/plain",
            MediaSource::inline(b"text".to_vec()),
        ),
    );
    assert_eq!(
        encode_multipart_media(&[conflicting], "b", limits()),
        Err(MediaCodecError::ConflictingFilename)
    );

    let wrapper_only_filename = MultipartMediaPart::media(
        "file",
        Some("wrapper.txt".to_owned()),
        ContentPart::file(None, "text/plain", MediaSource::inline(b"text".to_vec())),
    );
    assert_eq!(
        encode_multipart_media(&[wrapper_only_filename], "b", limits()),
        Err(MediaCodecError::ConflictingFilename)
    );

    let colliding = MultipartMediaPart::text(
        "prompt",
        "hello\r\n--b\r\nContent-Disposition: form-data; name=\"injected\"\r\n\r\nworld",
    );
    assert_eq!(
        encode_multipart_media(&[colliding], "b", limits()),
        Err(MediaCodecError::BoundaryCollision { part: 0 })
    );
    assert_eq!(
        encode_multipart_media(
            &[MultipartMediaPart::text("prompt", "ends here\r\n--b")],
            "b",
            limits()
        ),
        Err(MediaCodecError::BoundaryCollision { part: 0 })
    );

    let malformed = b"--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ndata";
    assert_eq!(
        decode_multipart_media(malformed, "multipart/form-data; boundary=b", limits()),
        Err(MediaCodecError::MalformedMultipart)
    );
}

#[test]
fn every_truncated_multipart_prefix_fails_without_panicking() {
    let parts = vec![
        MultipartMediaPart::text("model", "transcribe"),
        MultipartMediaPart::media(
            "file",
            Some("voice.wav".to_owned()),
            ContentPart::file(
                Some("voice.wav".to_owned()),
                "audio/wav",
                MediaSource::inline([0, 1, 2, 3, 4]),
            ),
        ),
    ];
    let encoded = encode_multipart_media(&parts, "truncate-boundary", limits())
        .expect("encode truncation fixture");
    for prefix_length in 0..encoded.body.len() {
        let result = decode_multipart_media(
            &encoded.body[..prefix_length],
            &encoded.content_type,
            limits(),
        );
        if prefix_length == encoded.body.len() - 2 {
            assert_eq!(
                result.expect("closing boundary without optional CRLF"),
                pooler_protocol::DecodedMultipartMedia {
                    parts: parts.clone()
                }
            );
        } else {
            assert!(result.is_err());
        }
    }
    assert_eq!(
        decode_multipart_media(&encoded.body, &encoded.content_type, limits())
            .expect("complete body"),
        pooler_protocol::DecodedMultipartMedia { parts }
    );
}
