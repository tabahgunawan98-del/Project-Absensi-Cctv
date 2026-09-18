class SpoofingMitigation:
    def is_spoof(self, image_data: bytes) -> bool:
        # Synthetic: basic check for spoof markers
        return b"spoof" in image_data
