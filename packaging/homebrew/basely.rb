# Template for Formula/basely.rb in fullstackspectrum/homebrew-basely.
# The release workflow renders it with packaging/homebrew/render_formula.py,
# which fills in the sdist url and sha256 from PyPI. Basely has no runtime
# dependencies, so there are no resource blocks. Edit everything else here
# rather than in the tap.
class Basely < Formula
  include Language::Python::Virtualenv

  desc "Compare container base images on vulnerabilities, size and fit"
  homepage "https://github.com/fullstackspectrum/basely"
  url "@URL@"
  sha256 "@SHA256@"
  license "Apache-2.0"

  # 3.14 reads zstd-compressed layers natively (Docker Hardened Images use them).
  depends_on "python@3.14"

  def install
    virtualenv_install_with_resources
  end

  # Advising needs the network, so the test sticks to what works offline.
  test do
    assert_match version.to_s, shell_output("#{bin}/basely --version")
    (testpath/"Dockerfile").write "RUN echo no FROM here\n"
    output = shell_output("#{bin}/basely advise #{testpath}/Dockerfile 2>&1", 2)
    assert_match "no FROM instruction found", output
  end
end
