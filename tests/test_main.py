import sys
from unittest import mock
from blhawk import main

@mock.patch('blhawk.inputLoader')
def test_main_with_real_raw_url(mock_input_loader):
    test_args = [
        'blhawk',
        '-u',
        'https://raw.githubusercontent.com/omranisecurity/BLHawk/refs/heads/main/tests/data/sample-server-response.txt'
    ]
    with mock.patch.object(sys, 'argv', test_args):
        main()
    mock_input_loader.assert_called_once_with(
        url='https://raw.githubusercontent.com/omranisecurity/BLHawk/refs/heads/main/tests/data/sample-server-response.txt'
    )
