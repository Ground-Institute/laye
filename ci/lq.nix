# The workflow that builds what lq runs, emitted to .github/workflows/lq.yml and never edited by hand:
#   nix eval --json --file ci/lq.nix | jq . > .github/workflows/lq.yml
#
# "I WANT LAYE TO FOLLOW LQ-STACK AND Q TO FOLLOW QQ-STACK"
# "JUST DO WHAT QNTX DOES"
#
# A push to lq-stack builds laye-front and laye-peer, puts them in the cache q
# takes nix builds from, and names the commit in the rolling release
# branch-lq-stack-latest. q's laye-pull reads that release
# (sbvh-nl/q.sbvh.nl infra/bootstrap/laye-pull.sh), as its qntx-pull reads
# QNTX's (teranos/QNTX ci/branch-latest.nix).
{
  name = "lq";
  on.push.branches = [ "lq-stack" ];
  concurrency = {
    group = "lq";
    cancel-in-progress = false;
  };
  permissions.contents = "write";
  jobs.build = {
    runs-on = "ubuntu-latest";
    steps = [
      { uses = "actions/checkout@v5"; }
      {
        uses = "cachix/install-nix-action@v31";
        "with".extra_nix_config = "experimental-features = nix-command flakes";
      }
      {
        uses = "cachix/cachix-action@v14";
        "with" = {
          name = "qntx";
          authToken = "\${{ secrets.CACHIX_AUTH_TOKEN }}";
        };
      }
      {
        name = "Build what lq runs";
        run = "nix build .#laye-front .#laye-peer --print-build-logs";
      }
      {
        name = "Name the commit in branch-lq-stack-latest";
        env.GH_TOKEN = "\${{ secrets.GITHUB_TOKEN }}";
        run = ''
          gh release delete branch-lq-stack-latest --cleanup-tag --yes 2>/dev/null || true
          printf '%s\n' "$GITHUB_SHA" > rev
          gh release create branch-lq-stack-latest rev \
            --prerelease \
            --title "lq-stack (rolling)" \
            --target "$GITHUB_SHA" \
            --notes "What lq runs: the tip of lq-stack, $GITHUB_SHA."
        '';
      }
    ];
  };
}
