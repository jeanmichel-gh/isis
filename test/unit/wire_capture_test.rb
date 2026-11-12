# frozen_string_literal: true
require_relative '../test_helper'
require 'isis/wire_capture/dissect'
require 'isis/wire_capture/cli'
require 'stringio'

class TestWireCapture < Minitest::Test
  PSNP = ['831101001a0100000013192168001001000900'].pack('H*').freeze
  def frame(pdu = PSNP)
    ['0180c2000014020000000001'].pack('H*') + [pdu.bytesize + 3].pack('n') + "\xfe\xfe\x03".b + pdu
  end

  def test_decodes_existing_pdu_and_keeps_frame_offsets
    bytes = frame + "\0\0".b
    result = ISIS::WireCapture::Dissect.frame(bytes)
    assert_match(/L1 PSNP/, result[:summary])
    assert_empty result[:errors]
    assert_equal bytes.bytesize, result[:length]
    assert_equal bytes.bytesize, result[:fields].sum { _1[:length] }
    isis = result[:fields].find { _1[:name] == 'IS-IS' }
    assert_equal 17, isis[:offset]
    assert_equal 'frame padding', result[:fields].last[:name]
    assert_equal 2, result[:fields].last[:length]
    tlv = isis[:children].find { _1[:offset] == 34 }
    assert_equal [34, 35], tlv[:children].map { _1[:offset] }
  end

  def test_truncation_retains_every_byte
    (0...frame.bytesize).each do |size|
      result = ISIS::WireCapture::Dissect.frame(frame[0, size])
      assert_equal size, result[:fields].sum { _1[:length] }, "size #{size}"
    end
  end

  def test_cli_reads_ethernet_pcap_and_reports_bad_link_types
    require 'tempfile'
    Tempfile.create do |file|
      file.binmode
      file.write([0xa1b2c3d4, 2, 4, 0, 0, 65535, 1].pack('VvvVVVV'))
      file.write([1, 123, frame.bytesize, frame.bytesize].pack('V4') + frame)
      file.flush
      output = StringIO.new
      assert_equal 0, ISIS::WireCapture::CLI.new(output).run(['capture', '-r', file.path])
      lines = output.string.lines.map { JSON.parse(_1) }
      assert_equal 'ethernet', lines.first['capture']['link']
      assert_equal frame.unpack1('H*'), lines.last['packet']['hex']
      assert_empty lines.last['packet']['errors']
    end
  end
end
