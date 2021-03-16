cloudbuild_cwd := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: gcloud-builds-triggers-create-review
gcloud-builds-triggers-create-review: $(cloudbuild_cwd)/triggers/review.yaml
	gcloud beta builds triggers create github --project einride-thesis-msg-integrity --trigger-config=$<
