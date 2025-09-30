//go:build lightspark

package handler

import (
	"context"
	"encoding/hex"
	"math/rand/v2"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightsparkdev/spark/common/keys"
	"github.com/lightsparkdev/spark/so/db"
	testutil "github.com/lightsparkdev/spark/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/distributed-lab/gripmock"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

func createTestTreeNodeAvailable(
	t *testing.T,
	ctx context.Context,
	client *ent.Client,
	tree *ent.Tree,
	keyshare *ent.SigningKeyshare,
	ownerIdentityPubKey, ownerSigningPubKey, verifyingPubKey keys.Public,
) *ent.TreeNode {
	validTx := createOldBitcoinTxBytes(t, ownerIdentityPubKey)
	leaf, err := client.TreeNode.Create().
		SetStatus(st.TreeNodeStatusAvailable).
		SetTree(tree).
		SetSigningKeyshare(keyshare).
		SetValue(1000).
		SetVerifyingPubkey(verifyingPubKey.Serialize()).
		SetOwnerIdentityPubkey(ownerIdentityPubKey.Serialize()).
		SetOwnerSigningPubkey(ownerSigningPubKey.Serialize()).
		SetRawTx(validTx).
		SetRawRefundTx(validTx).
		SetDirectTx(validTx).
		SetDirectRefundTx(validTx).
		SetDirectFromCpfpRefundTx(validTx).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)
	return leaf
}

func createValidTaprootSignature(t *testing.T, ownerIdentityPrivKey keys.Private, spendTxHash []byte) []byte {
	taprootKey := txscript.TweakTaprootPrivKey(*ownerIdentityPrivKey.ToBTCEC(), []byte{})

	sig, err := schnorr.Sign(taprootKey, spendTxHash)
	require.NoError(t, err, "failed to create schnorr signature")
	return sig.Serialize()
}

func TestInitiateStaticDepositUtxoSwap_ErrorWithNonOwnedTransferLeaves(t *testing.T) {
	testutil.RequireGripMock(t)
	defer func() { _ = gripmock.Clear() }()

	swapSuccessStub := map[string]any{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := db.ConnectToTestPostgres(t)

	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()
	differentOwnerPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public() // Different owner

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)
	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)
	tree := createTestTreeForClaim(t, ctx, ownerIdentityPubKey, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, rng, sessionCtx.Client, tree, keyshare, differentOwnerPubKey, ownerSigningPubKey) // Leaf owned by different user

	spendTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(t, cfg, utxo, leaf, rng, ownerIdentityPrivKey, ownerSigningPubKey, testSspSignature, spendTxBytes)

	_, err = handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	require.Error(t, err, "is not owned by sender")
}

func TestInitiateStaticDepositUtxoSwap_ErrorIfUtxoNotToStaticDepositAddress(t *testing.T) {
	testutil.RequireGripMock(t)
	defer func() { _ = gripmock.Clear() }()

	swapSuccessStub := map[string]any{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := db.ConnectToTestPostgres(t)
	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)
	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	// Create non-static deposit address
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	depositAddress, err = sessionCtx.Client.DepositAddress.UpdateOne(depositAddress).SetIsStatic(false).Save(ctx)
	require.NoError(t, err)

	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	tree := createTestTreeForClaim(t, ctx, ownerIdentityPubKey, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, rng, sessionCtx.Client, tree, keyshare, ownerIdentityPubKey, ownerSigningPubKey)

	spendTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(t, cfg, utxo, leaf, rng, ownerIdentityPrivKey, ownerSigningPubKey, testSspSignature, spendTxBytes)

	_, err = handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	require.ErrorContains(t, err, "unable to claim a deposit to a non-static address")
}

func TestInitiateStaticDepositUtxoSwap_UtxoNotConfirmed(t *testing.T) {
	ctx, sessionCtx := db.ConnectToTestPostgres(t)

	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	cfg.BitcoindConfigs["regtest"] = so.BitcoindConfig{
		DepositConfirmationThreshold: 100,
	}

	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 150)
	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)

	// confirmations = currentBlockHeight - utxoBlockHeight + 1
	// Needed: 150 - utxoBlockHeight + 1 < 100 => utxoBlockHeight > 51
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 52) // only 99 confirmations

	tree := createTestTreeForClaim(t, ctx, ownerIdentityPubKey, sessionCtx.Client)
	leaf := createTestTreeNode(t, ctx, rng, sessionCtx.Client, tree, keyshare)

	spendTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(t, cfg, utxo, leaf, rng, ownerIdentityPrivKey, ownerSigningPubKey, testSspSignature, spendTxBytes)

	_, err := handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	require.ErrorContains(t, err, "confirmations")
}

func TestInitiateStaticDepositUtxoSwap_ErrorIfUtxoSwapAlreadyInProgress(t *testing.T) {
	ctx, sessionCtx := db.ConnectToTestPostgres(t)

	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)
	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	// Create existing UTXO swap in progress
	_ = createTestUtxoSwap(t, ctx, rng, sessionCtx.Client, utxo, st.UtxoSwapStatusCreated)

	tree := createTestTreeForClaim(t, ctx, ownerIdentityPubKey, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, rng, sessionCtx.Client, tree, keyshare, ownerIdentityPubKey, ownerSigningPubKey)

	spendTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(t, cfg, utxo, leaf, rng, ownerIdentityPrivKey, ownerSigningPubKey, testSspSignature, spendTxBytes)

	_, err := handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	require.ErrorContains(t, err, "utxo swap is already registered")
}

func TestInitiateStaticDepositUtxoSwap_ErrorIfUtxoSwapAlreadyCompleted(t *testing.T) {
	ctx, sessionCtx := db.ConnectToTestPostgres(t)

	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)
	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	// Create existing completed UTXO swap
	_ = createTestUtxoSwap(t, ctx, rng, sessionCtx.Client, utxo, st.UtxoSwapStatusCompleted)

	tree := createTestTreeForClaim(t, ctx, ownerIdentityPubKey, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, rng, sessionCtx.Client, tree, keyshare, ownerIdentityPubKey, ownerSigningPubKey)

	spendTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(t, cfg, utxo, leaf, rng, ownerIdentityPrivKey, ownerSigningPubKey, testSspSignature, spendTxBytes)

	_, err := handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	require.ErrorContains(t, err, "utxo swap is already registered")
}

func TestInitiateStaticDepositUtxoSwap_CanCreateWithPreviousFailedRefund(t *testing.T) {
	testutil.RequireGripMock(t)
	defer func() { _ = gripmock.Clear() }()
	swapSuccessStub := map[string]any{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "initiate_transfer", nil, nil)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()

	ctx, sessionCtx := db.ConnectToTestPostgres(t)

	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	spendTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	spendTxSigHash, _, err := GetTxSigningInfo(ctx, utxo, spendTxBytes)
	require.NoError(t, err)

	aggregateFrostStubOutput := map[string]any{
		"signature": createValidTaprootSignature(t, ownerIdentityPrivKey, spendTxSigHash),
	}
	err = gripmock.AddStub("frost.FrostService", "aggregate_frost", nil, aggregateFrostStubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "utxo_swap_completed", nil, nil)
	require.NoError(t, err)

	// Create previous failed refund UtxoSwap
	previousUtxoSwap, err := sessionCtx.Client.UtxoSwap.Create().
		SetStatus(st.UtxoSwapStatusCancelled).
		SetRequestType(st.UtxoSwapRequestTypeRefund).
		SetUserIdentityPublicKey(ownerIdentityPubKey.Serialize()).
		SetCoordinatorIdentityPublicKey(cfg.IdentityPublicKey().Serialize()).
		SetUtxo(utxo).
		Save(ctx)
	require.NoError(t, err)

	tree := createTestTreeForClaim(t, ctx, ownerIdentityPubKey, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, rng, sessionCtx.Client, tree, keyshare, ownerIdentityPubKey, ownerSigningPubKey)

	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(t, cfg, utxo, leaf, rng, ownerIdentityPrivKey, ownerSigningPubKey, testSspSignature, spendTxBytes)

	resp, err := handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	// Commit tx before checking the result
	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	// Verify previous UtxoSwap still exists with cancelled status
	updatedPreviousSwap, err := sessionCtx.Client.UtxoSwap.Get(t.Context(), previousUtxoSwap.ID)
	require.NoError(t, err)
	assert.Equal(t, st.UtxoSwapStatusCancelled, updatedPreviousSwap.Status)

	// Verify new UtxoSwap was created
	allSwaps, err := sessionCtx.Client.UtxoSwap.Query().All(t.Context())
	require.NoError(t, err)
	assert.Greater(t, len(allSwaps), 1, "New UtxoSwap should be created despite previous failed refund")
}

func TestInitiateStaticDepositUtxoSwap_CanCreateWithPreviousFailedClaim(t *testing.T) {
	testutil.RequireGripMock(t)
	defer func() { _ = gripmock.Clear() }()

	swapSuccessStub := map[string]any{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "initiate_transfer", nil, nil)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerSigningPubKey := ownerSigningPrivKey.Public()

	err = gripmock.AddStub("spark_internal.SparkInternalService", "utxo_swap_completed", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := db.ConnectToTestPostgres(t)

	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)

	spendTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	spendTxSigHash, _, err := GetTxSigningInfo(ctx, utxo, spendTxBytes)
	require.NoError(t, err)

	aggregateFrostStubOutput := map[string]any{
		"signature": createValidTaprootSignature(t, ownerIdentityPrivKey, spendTxSigHash),
	}
	err = gripmock.AddStub("frost.FrostService", "aggregate_frost", nil, aggregateFrostStubOutput)
	require.NoError(t, err)

	// Create previous failed claim UtxoSwap
	previousUtxoSwap, err := sessionCtx.Client.UtxoSwap.Create().
		SetStatus(st.UtxoSwapStatusCancelled).
		SetRequestType(st.UtxoSwapRequestTypeFixedAmount).
		SetUserIdentityPublicKey(ownerIdentityPubKey.Serialize()).
		SetCoordinatorIdentityPublicKey(cfg.IdentityPublicKey().Serialize()).
		SetUtxo(utxo).
		Save(ctx)
	require.NoError(t, err)

	tree := createTestTreeForClaim(t, ctx, ownerIdentityPubKey, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, rng, sessionCtx.Client, tree, keyshare, ownerIdentityPubKey, ownerSigningPubKey)

	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(t, cfg, utxo, leaf, rng, ownerIdentityPrivKey, ownerSigningPubKey, testSspSignature, spendTxBytes)

	resp, err := handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	// Commit tx before checking the result
	tx, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	err = tx.Commit()
	require.NoError(t, err)

	// Verify previous UtxoSwap still exists with cancelled status
	updatedPreviousSwap, err := sessionCtx.Client.UtxoSwap.Get(t.Context(), previousUtxoSwap.ID)
	require.NoError(t, err)
	assert.Equal(t, st.UtxoSwapStatusCancelled, updatedPreviousSwap.Status)

	// Verify new UtxoSwap was created
	allSwaps, err := sessionCtx.Client.UtxoSwap.Query().All(t.Context())
	require.NoError(t, err)
	assert.Greater(t, len(allSwaps), 1, "New UtxoSwap should be created despite previous failed claim")
}

func TestInitiateStaticDepositUtxoSwap_TransferFailureCancelsUtxoSwap(t *testing.T) {
	testutil.RequireGripMock(t)
	defer func() { _ = gripmock.Clear() }()

	swapSuccessStub := map[string]any{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	// Mock transfer failure
	transferFailureStub := map[string]any{
		"error": "Failed to create transfer",
	}
	err = gripmock.AddStub("spark_internal.SparkInternalService", "initiate_transfer", nil, transferFailureStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	// Mock rollback success
	err = gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := db.ConnectToTestPostgres(t)

	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerSigningPubKey := ownerSigningPrivKey.Public()

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)
	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)
	tree := createTestTreeForClaim(t, ctx, ownerIdentityPubKey, sessionCtx.Client)
	leaf := createTestTreeNodeForStaticDeposit(t, ctx, rng, sessionCtx.Client, tree, keyshare, ownerIdentityPubKey, ownerSigningPubKey)

	spendTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(t, cfg, utxo, leaf, rng, ownerIdentityPrivKey, ownerSigningPubKey, testSspSignature, spendTxBytes)

	_, err = handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	require.ErrorContains(t, err, "failed to create transfer")

	// Verify UtxoSwap was created initially but then cancelled due to transfer failure
	utxoSwaps, err := sessionCtx.Client.UtxoSwap.Query().All(ctx)
	require.NoError(t, err)

	if len(utxoSwaps) > 0 {
		// If UtxoSwap was created, it should be cancelled
		utxoSwap := utxoSwaps[0]
		assert.Equal(t, st.UtxoSwapStatusCancelled, utxoSwap.Status)
	}
}

func TestInitiateStaticDepositUtxoSwap_ErrorIfWrongVerificationKey(t *testing.T) {
	testutil.RequireGripMock(t)
	defer func() { _ = gripmock.Clear() }()

	swapSuccessStub := map[string]any{
		"UtxoDepositAddress": "bc1ptest_static_deposit_address_for_testing",
	}
	err := gripmock.AddStub("spark_internal.SparkInternalService", "create_static_deposit_utxo_swap", nil, swapSuccessStub)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "initiate_transfer", nil, nil)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round1", nil, frostRound1StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "frost_round2", nil, frostRound2StubOutput)
	require.NoError(t, err)

	err = gripmock.AddStub("spark_internal.SparkInternalService", "rollback_utxo_swap", nil, nil)
	require.NoError(t, err)

	ctx, sessionCtx := db.ConnectToTestPostgres(t)
	cfg := setUpTestConfigWithRegtestNoAuthz(t)
	handler := NewStaticDepositHandler(cfg)

	createTestBlockHeight(t, ctx, sessionCtx.Client, 100)

	rng := rand.NewChaCha8([32]byte{})
	ownerIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPubKey := ownerIdentityPrivKey.Public()
	ownerSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()
	verifyingPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public()
	wrongSigningPubKey := keys.MustGeneratePrivateKeyFromRand(rng).Public() // Wrong verification key

	keyshare := createTestSigningKeyshare(t, ctx, rng, sessionCtx.Client)
	depositAddress := createTestStaticDepositAddress(t, ctx, sessionCtx.Client, keyshare, ownerIdentityPubKey, ownerSigningPubKey)
	utxo := createTestUtxo(t, ctx, sessionCtx.Client, depositAddress, 100)
	tree := createTestTreeForClaim(t, ctx, ownerIdentityPubKey, sessionCtx.Client)
	leaf := createTestTreeNodeAvailable(t, ctx, sessionCtx.Client, tree, keyshare, ownerIdentityPubKey, ownerSigningPubKey, verifyingPubKey)

	spendTxBytes := createValidBitcoinTxBytes(t, ownerIdentityPubKey)
	testSspSignature, _ := hex.DecodeString("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")

	req := createMockStaticDepositUtxoSwapRequest(t, cfg, utxo, leaf, rng, ownerIdentityPrivKey, ownerSigningPubKey, testSspSignature, spendTxBytes)

	// Change verification key to wrong one
	req.SpendTxSigningJob.SigningPublicKey = wrongSigningPubKey.Serialize()

	_, err = handler.InitiateStaticDepositUtxoSwap(ctx, cfg, req)
	require.ErrorContains(t, err, "deposit address owner signing pubkey does not match the signing public key")
}
