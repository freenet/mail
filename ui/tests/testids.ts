import { readFileSync } from "node:fs";
import { join } from "node:path";

// Single source of truth for `data-testid` values, shared verbatim
// with the Rust UI via `ui/branding/testids.json`. The Rust side
// declares matching `pub(crate) const`s in `ui/src/testid.rs` and
// asserts agreement via a unit test (`testid::tests::json_matches_rust_consts`).
//
// Use the exported `TID` map in Playwright specs as
// `[data-testid="${TID.fmIdRow}"]` so a rename in either source
// trips one place instead of N call sites.
interface TestIds {
  fmApp: string;
  fmAvatar: string;
  fmLogout: string;
  fmSearch: string;
  fmComposeBtn: string;
  fmList: string;
  fmMsgCard: string;
  fmDraftCard: string;
  fmSentCard: string;
  fmArchiveCard: string;
  fmReply: string;
  fmDelete: string;
  fmArchive: string;
  fmSentBody: string;
  fmSentDelivery: string;
  fmSentFingerprint: string;
  fmSentForward: string;
  fmSentReply: string;
  fmSentResend: string;
  fmArchiveBody: string;
  fmArchiveDelete: string;
  fmArchiveReply: string;
  fmArchiveUnarchive: string;
  fmComposeSheet: string;
  fmSend: string;
  fmToast: string;
  fmActionCreate: string;
  fmActionImport: string;
  fmCreateAliasInput: string;
  fmCreateConfirm: string;
  fmCreateSubmit: string;
  fmVerifyCheck: string;
  fmRestoreFile: string;
  fmRestoreSubmit: string;
  fmIdRow: string;
  fmIdOpen: string;
  fmIdCreate: string;
  fmIdBackup: string;
  fmIdRestore: string;
  fmIdRename: string;
  fmIdShare: string;
  fmRenameInput: string;
  fmRenameSubmit: string;
  fmShareModal: string;
  fmShareCopy: string;
  fmContactImport: string;
  fmImportContactModal: string;
  fmImportFp: string;
  fmImportSubmit: string;
  fmContactVerify: string;
  fmVerifyContactModal: string;
  fmVerifyContactSubmit: string;
}

export const TID: TestIds = JSON.parse(
  readFileSync(join(__dirname, "..", "branding", "testids.json"), "utf8"),
);
