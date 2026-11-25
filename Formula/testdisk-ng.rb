class TestdiskNg < Formula
  desc "Partition recovery and disk repair tool (Modern TUI edition)"
  homepage "https://github.com/cwmoriarty/TestDisk-NG"
  url "https://github.com/cwmoriarty/TestDisk-NG/archive/refs/tags/v7.4.0-ng.tar.gz"
  sha256 "01d4171ca04969923a3b1fdbc91cf0e9cc820e8d6a584b3d12b7116d660fca6c"
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
