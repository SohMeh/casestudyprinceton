"""Small readers that turn raw artifacts into facts: quoted mail, lock files, an earlier disk layout."""
from datetime import datetime

from casereplay.examiners.activity import _text_lines, search_query, split_quotes
from casereplay.examiners.recovery import _fit_layout


def test_reply_keeps_the_messages_it_quotes():
    html = (b"<html><head><style>p{margin:0}</style></head><body><p>Okay, I got it.</p>"
            b"<div><p><b>From:</b> iaman <br><b>Sent:</b> Monday, March 23,\r\n 2015 3:19 PM<br><b>To:</b> spy<br>"
            b"<b>Subject:</b> RE: Good job, buddy.</p></div><p>This is a sample.</p>"
            b"<div><p><b>From:</b> spy <br><b>Sent:</b> Monday, March 23, 2015 3:15 PM<br><b>To:</b> iaman<br>"
            b"<b>Subject:</b> Good job, buddy.</p></div><p>I need a more detailed data.</p></body></html>")
    own, quotes = split_quotes(_text_lines(html))
    assert own == "Okay, I got it."
    assert [(q["from"], q["subject"], q["body"]) for q in quotes] == [
        ("iaman", "RE: Good job, buddy.", "This is a sample."),
        ("spy", "Good job, buddy.", "I need a more detailed data.")]
    assert quotes[0]["sent_local"] == datetime(2015, 3, 23, 15, 19)


def test_plain_text_reply():
    plain = (b"I am trying.\r\n\r\n-----Original Message-----\r\nFrom: spy \r\nSent: Tuesday, March 24, 2015 3:33 PM\r\n"
             b"To: iaman\r\nSubject: Watch out!\r\n\r\nUSB device may be easily detected.\r\n")
    own, quotes = split_quotes(_text_lines(plain))
    assert own == "I am trying."
    assert quotes[0]["subject"] == "Watch out!" and quotes[0]["body"] == "USB device may be easily detected."


def test_earlier_layout_is_found_from_matching_sizes():
    base, size = 315392, 16384
    pairs = [(c, base + size * c) for c in (12834, 13211, 13711, 15814)]
    assert _fit_layout(pairs) == (base, size)
    assert _fit_layout(pairs[:1]) is None
    assert _fit_layout([(10, 5000), (11, 5003), (12, 9000)]) is None       # not one layout


def test_search_queries_are_read_from_urls():
    assert search_query("https://www.google.com/search?q=data+leakage+methods&oq=x") == ("Google", "data leakage methods")
    assert search_query("http://www.bing.com/search?q=DLP%20DRM&src=IE") == ("Bing", "DLP DRM")
    assert search_query("https://example.com/?q=nothing") is None
