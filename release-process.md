# Release process

Anyone with write access to `Consensys-Incorporated/web3signer` can cut a release. Pushing a version tag
starts the `CI` workflow (`.github/workflows/ci_main.yml`), which builds and tests the tagged commit,
publishes the Docker images and creates a **draft** GitHub release. The release reaches users once a
maintainer has reviewed the draft and published it.

## Version names

- Release: `X.Y.Z`, for example `26.8.0`.
- Release candidate: `X.Y.Z-RCn`, for example `26.8.0-RC1`, deployed internally before the final release.
  The uppercase `-RC` marks the GitHub release as a pre-release and keeps Docker `latest` on the last final
  release.

## 1. Prepare `CHANGELOG.md`

Rename `## Upcoming Release` to `## X.Y.Z` and merge the change to `master`. Release candidates use the
heading of the version they lead to.

The draft's release notes are the section under the first `##` heading. The second `##` heading must be the
previous release: the "Full Changelog" link in the notes compares against it.

## 2. Tag and push

Start with a release candidate on the commit to release, usually the tip of `master`:

```bash
git fetch upstream
git tag -a 26.8.0-RC1 -m "26.8.0-RC1" upstream/master
git push upstream 26.8.0-RC1
```

Once the candidate has passed internal deployment, tag the same commit with the final version, so that the
release contains exactly the code that was tested:

```bash
git tag -a 26.8.0 -m "26.8.0" '26.8.0-RC1^{commit}'
git push upstream 26.8.0
```

Type `^{commit}` exactly as shown; it is git syntax, not a placeholder for a hash. `26.8.0-RC1^{commit}` means
"the commit that the `26.8.0-RC1` tag points to", and `git rev-parse '26.8.0-RC1^{commit}'` prints that
commit's hash, which works in its place. Without `^{commit}`, git would make `26.8.0` point to the
`26.8.0-RC1` tag itself (a tag of a tag) instead of to the commit.

Push one tag at a time. GitHub starts no workflow when more than three tags are pushed at once.

## 3. What the workflow does

The run takes about 20 minutes:

1. It stops if the tag isn't the version the build computes (possible when another tag points at the same
   commit), or if a published release already exists for that version.
2. It builds the distributions and runs the tests.
3. It pushes and signs the Docker images `consensys/web3signer:X.Y.Z` and `X.Y.Z-distroless`, and for final
   releases also moves `latest` and `latest-distroless` to them. They are public from this point on, before
   anyone has reviewed the release.
4. It records signed build provenance for `web3signer-X.Y.Z.tar.gz` and `web3signer-X.Y.Z.zip` (a GitHub
   artifact attestation), then creates the draft release with the notes, those two files and their
   `.sha256` files. The notes include the commands users run to verify the files.

## 4. Review and publish the draft

1. Open the draft under **Releases**. Drafts are only visible to people with write access.
2. Check the notes, the four files, and that a release candidate is marked as a pre-release. Edit the notes
   if needed; re-running the workflow keeps your edits.
3. Click **Publish release**. Tick **Set as the latest release** for final releases only.

## Redoing a release before it is published

1. Delete the draft, then the tag, in that order:

   ```bash
   gh release delete 26.8.0-RC1 --repo Consensys-Incorporated/web3signer --cleanup-tag --yes
   git tag -d 26.8.0-RC1
   ```

2. Fix the problem on `master`, then repeat steps 2 to 4.

Pushing the tag again cancels any run still in progress for the old tag. The new run replaces the Docker
images of that version; anyone who pulled them in between keeps the old image.

## After a release is published

Never delete, move or re-push the tag of a published release, and never replace its files. Fix problems in a
new version: the next patch release or release candidate. The workflow refuses to rebuild a version that is
already published.

Release immutability makes GitHub enforce this. It is a repository setting that a repository admin turns on
under **Settings** → **Releases** → **Enable release immutability**. It covers releases published while it is
on, and they stay immutable if it is turned off again. For those releases:

- The tag can't be moved or deleted, and the files can't be changed or removed.
- Deleting the release doesn't free the version: its tag name can never be used again.
- The title, the notes and the pre-release and latest flags stay editable.
- Users can check a release with `gh release verify X.Y.Z` and `gh release verify-asset X.Y.Z <file>`. The
  build provenance check, `gh attestation verify <file> --repo Consensys-Incorporated/web3signer`, doesn't
  depend on immutability.

## Deprecating a published release

A published release that must not be used, for example one with a security issue, stays on the releases
page. Deprecate it instead:

1. Release the fix as a new version first, so that the latest release and the Docker `latest` tag point to
   it.
2. Edit the bad release: add `(DEPRECATED)` to its title and put a warning at the top of its notes:

   ```markdown
   > [!CAUTION]
   > Deprecated: <reason>. Upgrade to [26.8.1](https://github.com/Consensys-Incorporated/web3signer/releases/tag/26.8.1).
   ```

3. For a security issue, publish a security advisory (**Security** > **Advisories**) that lists the affected
   versions and the fixed version, and mention it in the fix's `CHANGELOG.md` entry.
4. Keep the Docker image tags of the deprecated version. Deleting them breaks deployments pinned to that
   version instead of upgrading them.
