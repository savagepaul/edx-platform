""" Tests for videoalpha"""
import unittest
from pkg_resources import resource_string
from .import get_test_system
from xmodule.videoalpha_module import VideoAlphaDescriptor


class VideoAlphaDescriptorTest(unittest.TestCase):
    """Test for VideoAlphaDescriptor"""

    def setUp(self):
        system = get_test_system()
        self.descriptor = VideoAlphaDescriptor(
            runtime=system,
            model_data={})

    def test_get_context(self):
        """"test get_context"""
        correct_tabs = [
            {
                'name': "XML",
                'template': "videoalpha/codemirror-edit.html",
                'css': {'scss': [resource_string(__name__,
                        '../css/tabs/codemirror.scss')]},
                'current': True,
            },
            {
                'name': "Subtitles",
                'template': "videoalpha/subtitles.html",
            },
            {
                'name': "Settings",
                'template': "tabs/video-metadata-edit-tab.html"
            }
        ]
        rendered_context = self.descriptor.get_context()
        self.assertListEqual(rendered_context['tabs'], correct_tabs)

