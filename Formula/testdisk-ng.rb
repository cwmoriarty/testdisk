class TestdiskNg < Formula
  desc "Partition recovery and disk repair tool (Modern TUI edition)"
  homepage "https://github.com/cwmoriarty/TestDisk-NG"
  url "https://github.com/cwmoriarty/TestDisk-NG/archive/refs/tags/v7.2.0-ng.tar.gz"
  sha256 "4a1848f8feb1f6df2a498616c155274e1114a0a87cd92370fc7c49107f0c711a"
  license "GPL-2.0-or-later"
  head "https://github.com/cwmoriarty/TestDisk-NG.git", branch: "main"

  depends_on "autoconf" => :build
  depends_on "automake" => :build
  depends_on "libtool" => :build
  depends_on "pkg-config" => :build
  depends_on "ncurses"

  def install
    system "./autogen.sh"
    system "./configure", *std_configure_args,
                          "--disable-silent-rules",
                          "--without-ewf",
                          "--without-ntfs3g"
    system "make", "install"
  end

  test do
    assert_match "TestDisk-NG", shell_output("#{bin}/testdisk-ng /version")
    assert_match "PhotoRec-NG", shell_output("#{bin}/photorec-ng /version")
  end
end
