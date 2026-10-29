#include <sys/types.h>

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define MAX_DEVICES 256
#define ADDRESS_LEN 48
#define MIN_SAMPLES 20

#define MAX_SIGNATURES 2048
#define SIGNATURE_LEN 512
#define MAX_PAYLOADS 2048
#define PAYLOAD_LEN 512

typedef struct {
	char field[32];
	char payload[PAYLOAD_LEN];
	char addresses[MAX_DEVICES][ADDRESS_LEN];
	size_t address_count;
	size_t observations;
} PayloadMatch;

static int load_payload_matches(const char *path, PayloadMatch **matches_out,
				size_t *match_count_out);

typedef struct {
	char field[32];
	char payload[SIGNATURE_LEN];
} PayloadSignature;

static PayloadSignature baseline_signatures[MAX_SIGNATURES];
static PayloadSignature observed_signatures[MAX_SIGNATURES];

typedef struct {
	char address[ADDRESS_LEN];
	size_t samples;

	double sum_rssi;
	double sum_rssi_sq;
	double sum_manufacturer_bytes;
	double sum_service_count;
	double sum_service_data_bytes;
} Device;

typedef struct {
	char reference_address[ADDRESS_LEN];
	size_t samples;

	double mean_rssi;
	double sd_rssi;
	double mean_manufacturer_bytes;
	double mean_service_count;
	double mean_service_data_bytes;
} Fingerprint;

static double mean(double sum, size_t n)
{
	return n ? sum / (double)n : 0.0;
}

static double rssi_sd(const Device *d)
{
	double avg = mean(d->sum_rssi, d->samples);
	double variance = mean(d->sum_rssi_sq, d->samples) - avg * avg;

	/* Protect against tiny negative floating-point errors. */
	if (variance < 0.0)
		variance = 0.0;

	return sqrt(variance);
}

static Device *find_device(Device devices[], size_t count, const char *address)
{
	for (size_t i = 0; i < count; i++) {
		if (strcmp(devices[i].address, address) == 0)
			return &devices[i];
	}

	return NULL;
}

static int load_observations(const char *path, Device devices[],
			     size_t *device_count)
{
	FILE *file = fopen(path, "r");

	if (!file) {
		perror(path);
		return -1;
	}

	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	size_t line_number = 0;
	size_t total = 0;
	*device_count = 0;

	while ((length = getline(&line, &capacity, file)) != -1) {
		(void)length;
		line_number++;

		/* Skip the TSV header. */
		if (line_number == 1)
			continue;

		double timestamp;
		char address[ADDRESS_LEN];
		double rssi;
		double manufacturer_bytes;
		double service_count;
		double service_data_bytes;

		int fields = sscanf(line, "%lf\t%47[^\t]\t%lf\t%lf\t%lf\t%lf",
				    &timestamp, address, &rssi,
				    &manufacturer_bytes, &service_count,
				    &service_data_bytes);

		(void)timestamp;

		if (fields != 6) {
			fprintf(stderr, "Skipping malformed row %zu\n",
				line_number);
			continue;
		}

		Device *d = find_device(devices, *device_count, address);

		if (!d) {
			if (*device_count >= MAX_DEVICES) {
				fprintf(stderr, "Device limit (%d) exceeded\n",
					MAX_DEVICES);
				free(line);
				fclose(file);
				return -1;
			}

			d = &devices[(*device_count)++];
			memset(d, 0, sizeof(*d));

			snprintf(d->address, sizeof(d->address), "%s", address);
		}

		d->samples++;
		d->sum_rssi += rssi;
		d->sum_rssi_sq += rssi * rssi;
		d->sum_manufacturer_bytes += manufacturer_bytes;
		d->sum_service_count += service_count;
		d->sum_service_data_bytes += service_data_bytes;

		total++;
	}

	free(line);

	if (ferror(file)) {
		perror("Reading observations");
		fclose(file);
		return -1;
	}

	if (fclose(file) != 0) {
		perror("Closing observations");
		return -1;
	}

	printf("Loaded %zu observations from %s\n", total, path);

	return 0;
}

static Fingerprint make_fingerprint(const Device *d)
{
	Fingerprint f = { 0 };

	snprintf(f.reference_address, sizeof(f.reference_address), "%s",
		 d->address);

	f.samples = d->samples;
	f.mean_rssi = mean(d->sum_rssi, d->samples);
	f.sd_rssi = rssi_sd(d);
	f.mean_manufacturer_bytes = mean(d->sum_manufacturer_bytes, d->samples);
	f.mean_service_count = mean(d->sum_service_count, d->samples);
	f.mean_service_data_bytes = mean(d->sum_service_data_bytes, d->samples);

	return f;
}

static void print_fingerprint(const Fingerprint *f)
{
	printf("\nAddress: %s\n", f->reference_address);
	printf("Samples: %zu\n", f->samples);
	printf("Mean RSSI: %.2f dBm\n", f->mean_rssi);
	printf("RSSI standard deviation: %.2f dB\n", f->sd_rssi);
	printf("Mean manufacturer bytes: %.2f\n", f->mean_manufacturer_bytes);
	printf("Mean service count: %.2f\n", f->mean_service_count);
	printf("Mean service-data bytes: %.2f\n", f->mean_service_data_bytes);
}

static int save_baseline(const char *path, const Fingerprint *f)
{
	FILE *file = fopen(path, "w");

	if (!file) {
		perror(path);
		return -1;
	}

	int result = fprintf(file,
			     "%s\t%zu\t%.10f\t%.10f\t%.10f\t%.10f\t%.10f\n",
			     f->reference_address, f->samples, f->mean_rssi,
			     f->sd_rssi, f->mean_manufacturer_bytes,
			     f->mean_service_count, f->mean_service_data_bytes);

	if (result < 0) {
		perror("Writing baseline");
		fclose(file);
		return -1;
	}

	if (fclose(file) != 0) {
		perror("Closing baseline");
		return -1;
	}

	printf("Baseline saved to %s\n", path);
	return 0;
}

static int load_baseline(const char *path, Fingerprint *f)
{
	FILE *file = fopen(path, "r");

	if (!file) {
		perror(path);
		return -1;
	}

	int fields = fscanf(file, "%47s\t%zu\t%lf\t%lf\t%lf\t%lf\t%lf",
			    f->reference_address, &f->samples, &f->mean_rssi,
			    &f->sd_rssi, &f->mean_manufacturer_bytes,
			    &f->mean_service_count,
			    &f->mean_service_data_bytes);

	fclose(file);

	if (fields != 7) {
		fprintf(stderr, "Invalid baseline file\n");
		return -1;
	}

	return 0;
}

static int command_summary(const char *path)
{
	Device devices[MAX_DEVICES] = { 0 };
	size_t count = 0;

	if (load_observations(path, devices, &count) != 0)
		return 1;

	printf("\n%-20s %8s %12s %10s\n", "ADDRESS", "SAMPLES", "MEAN RSSI",
	       "RSSI SD");

	for (size_t i = 0; i < count; i++) {
		Fingerprint f = make_fingerprint(&devices[i]);

		printf("%-20s %8zu %9.2f dBm %8.2f\n", f.reference_address,
		       f.samples, f.mean_rssi, f.sd_rssi);
	}

	printf("\nDistinct addresses: %zu\n", count);
	return 0;
}

static int command_report(const char *path)
{
	Device devices[MAX_DEVICES] = { 0 };
	size_t device_count = 0;
	size_t total_observations = 0;
	size_t eligible = 0;
	size_t shared_signatures = 0;
	size_t correlated_address_count = 0;
	size_t supporting_observations = 0;
	char correlated_addresses[MAX_DEVICES][ADDRESS_LEN] = { 0 };

	if (load_observations(path, devices, &device_count) != 0)
		return 1;

	for (size_t i = 0; i < device_count; i++) {
		total_observations += devices[i].samples;

		if (devices[i].samples >= MIN_SAMPLES)
			eligible++;
	}

	printf("\n=== RogueNet Evaluation Report ===\n");
	printf("Dataset: %s\n", path);
	printf("Total observations: %zu\n", total_observations);
	printf("Distinct addresses: %zu\n", device_count);
	printf("Eligible addresses (>= %d samples): %zu\n", MIN_SAMPLES,
	       eligible);
	printf("Excluded addresses (< %d samples): %zu\n", MIN_SAMPLES,
	       device_count - eligible);

	printf("\n--- Address Breakdown ---\n");

	for (size_t i = 0; i < device_count; i++) {
		printf("%-20s %4zu samples  %s\n", devices[i].address,
		       devices[i].samples,
		       devices[i].samples >= MIN_SAMPLES ? "ELIGIBLE" :
							   "INSUFFICIENT DATA");
	}

	PayloadMatch *matches = NULL;
	size_t match_count = 0;

	if (load_payload_matches(path, &matches, &match_count) != 0)
		return 1;

	for (size_t i = 0; i < match_count; i++) {
		PayloadMatch *match = &matches[i];

		if (match->address_count < 2)
			continue;

		shared_signatures++;
		supporting_observations += match->observations;

		for (size_t j = 0; j < match->address_count; j++) {
			int seen = 0;

			for (size_t k = 0; k < correlated_address_count; k++) {
				if (strcmp(correlated_addresses[k],
					   match->addresses[j]) == 0) {
					seen = 1;
					break;
				}
			}

			if (!seen && correlated_address_count < MAX_DEVICES) {
				snprintf(correlated_addresses
						 [correlated_address_count],
					 ADDRESS_LEN, "%s",
					 match->addresses[j]);
				correlated_address_count++;
			}
		}
	}

	printf("\n--- Shared Payload Details ---\n");

	int has_shared_payloads = 0;

	for (size_t i = 0; i < match_count; i++) {
		PayloadMatch *match = &matches[i];

		if (match->address_count < 2)
			continue;

		has_shared_payloads = 1;

		printf("\nField: %s\n", match->field);
		printf("Payload: %s\n", match->payload);
		printf("Distinct addresses: %zu\n", match->address_count);
		printf("Supporting observations: %zu\n", match->observations);
		printf("Addresses:\n");

		for (size_t j = 0; j < match->address_count; j++)
			printf("  %s\n", match->addresses[j]);
	}

	if (!has_shared_payloads)
		printf("No payload signatures shared across multiple addresses.\n");

	free(matches);

	printf("\n--- Payload Correlation Summary ---\n");
	printf("Shared payload signatures: %zu\n", shared_signatures);
	printf("Distinct addresses involved: %zu\n", correlated_address_count);
	printf("Supporting observations (summed across signatures): %zu\n",
	       supporting_observations);

	printf("\nNote: Eligibility indicates sample count only, "
	       "not fingerprint reliability.\n");

	return 0;
}

static int command_baseline(const char *input, const char *address,
			    const char *output)
{
	Device devices[MAX_DEVICES] = { 0 };
	size_t count = 0;

	if (load_observations(input, devices, &count) != 0)
		return 1;

	Device *d = find_device(devices, count, address);

	if (!d) {
		fprintf(stderr, "Address not found: %s\n", address);
		return 1;
	}

	if (d->samples < MIN_SAMPLES) {
		fprintf(stderr, "Only %zu samples; need at least %d\n",
			d->samples, MIN_SAMPLES);
		return 1;
	}

	Fingerprint f = make_fingerprint(d);
	print_fingerprint(&f);

	return save_baseline(output, &f) != 0;
}

static int compare_payloads(const char *input_path, const char *address,
			    const char *baseline_path);

static int command_check(const char *input, const char *address,
			 const char *baseline_path,
			 const char *payload_baseline_path)
{
	Device devices[MAX_DEVICES] = { 0 };
	size_t count = 0;
	Fingerprint baseline = { 0 };

	if (load_observations(input, devices, &count) != 0)
		return 1;

	if (load_baseline(baseline_path, &baseline) != 0)
		return 1;

	Device *d = find_device(devices, count, address);

	if (!d) {
		fprintf(stderr, "No observations for candidate: %s\n", address);
		return 1;
	}

	if (d->samples < MIN_SAMPLES) {
		fprintf(stderr,
			"Only %zu candidate samples; need at least %d\n",
			d->samples, MIN_SAMPLES);
		return 1;
	}

	Fingerprint current = make_fingerprint(d);

	printf("\nFeature comparison\n");
	printf("%-28s %12s %12s\n", "FEATURE", "BASELINE", "CURRENT");

	printf("%-28s %12.2f %12.2f\n", "Mean RSSI", baseline.mean_rssi,
	       current.mean_rssi);
	printf("%-28s %12.2f %12.2f\n", "RSSI standard deviation",
	       baseline.sd_rssi, current.sd_rssi);
	printf("%-28s %12.2f %12.2f\n", "Manufacturer bytes",
	       baseline.mean_manufacturer_bytes,
	       current.mean_manufacturer_bytes);
	printf("%-28s %12.2f %12.2f\n", "Service count",
	       baseline.mean_service_count, current.mean_service_count);
	printf("%-28s %12.2f %12.2f\n", "Service-data bytes",
	       baseline.mean_service_data_bytes,
	       current.mean_service_data_bytes);

	int deviations = 0;

	if (fabs(current.mean_rssi - baseline.mean_rssi) > 15.0)
		deviations++;

	if (fabs(current.mean_manufacturer_bytes -
		 baseline.mean_manufacturer_bytes) > 8.0)
		deviations++;

	if (fabs(current.mean_service_count - baseline.mean_service_count) >
	    2.0)
		deviations++;

	if (fabs(current.mean_service_data_bytes -
		 baseline.mean_service_data_bytes) > 8.0)
		deviations++;

	printf("\nFeature deviations: %d\n", deviations);

	if (deviations >= 2) {
		printf("Result: BEHAVIORAL DEVIATION DETECTED\n");
	} else {
		printf("Result: NO SIGNIFICANT DEVIATION\n");
	}

	int payload_result = 0;

	if (payload_baseline_path != NULL) {
		printf("\n");
		payload_result =
			compare_payloads(input, address, payload_baseline_path);

		if (payload_result < 0)
			return 1;
	}

	printf("\nCombined assessment: ");

	if (deviations >= 2 && payload_result == 1) {
		printf("BEHAVIORAL AND PAYLOAD DEVIATIONS\n");
	} else if (deviations >= 2) {
		printf("BEHAVIORAL DEVIATION\n");
	} else if (payload_result == 1) {
		printf("PAYLOAD DEVIATION\n");
	} else {
		printf("NO OBSERVED DEVIATIONS\n");
	}

	printf("This assessment is not proof of impersonation.\n");
	return 0;
}

static int address_seen(const PayloadMatch *match, const char *address)
{
	for (size_t i = 0; i < match->address_count; i++) {
		if (strcmp(match->addresses[i], address) == 0)
			return 1;
	}
	return 0;
}

static size_t split_tsv(char *line, char *columns[], size_t max_columns)
{
	size_t count = 0;
	columns[count++] = line;

	for (char *p = line; *p; p++) {
		if (*p == '\n' || *p == '\r') {
			*p = '\0';
			break;
		}

		if (*p == '\t') {
			*p = '\0';

			if (count >= max_columns)
				return count;

			columns[count++] = p + 1;
		}
	}

	return count;
}

static int signature_exists(const PayloadSignature signatures[], size_t count,
			    const char *field, const char *payload)
{
	for (size_t i = 0; i < count; i++) {
		if (strcmp(signatures[i].field, field) == 0 &&
		    strcmp(signatures[i].payload, payload) == 0) {
			return 1;
		}
	}

	return 0;
}

static void add_payload_values(PayloadSignature signatures[], size_t *count,
			       const char *field, const char *value)
{
	if (value == NULL || value[0] == '\0' || strcmp(value, "NA") == 0) {
		return;
	}

	char copy[SIGNATURE_LEN];

	if (strlen(value) >= sizeof(copy)) {
		fprintf(stderr, "Warning: payload too long; skipped\n");
		return;
	}

	snprintf(copy, sizeof(copy), "%s", value);

	char *saveptr = NULL;
	char *payload = strtok_r(copy, ";", &saveptr);

	while (payload != NULL) {
		if (payload[0] != '\0' &&
		    !signature_exists(signatures, *count, field, payload)) {
			if (*count >= MAX_SIGNATURES) {
				fprintf(stderr,
					"Warning: signature limit reached\n");
				return;
			}

			snprintf(signatures[*count].field,
				 sizeof(signatures[*count].field), "%s", field);
			snprintf(signatures[*count].payload,
				 sizeof(signatures[*count].payload), "%s",
				 payload);
			(*count)++;
		}

		payload = strtok_r(NULL, ";", &saveptr);
	}
}

static int load_payload_matches(const char *path, PayloadMatch **matches_out,
				size_t *match_count_out)
{
	FILE *file = fopen(path, "r");

	if (!file) {
		perror(path);
		return -1;
	}

	PayloadMatch *matches = calloc(MAX_PAYLOADS, sizeof(*matches));
	if (!matches) {
		perror("calloc");
		fclose(file);
		return -1;
	}

	size_t match_count = 0;
	char *line = NULL;
	size_t capacity = 0;
	size_t line_number = 0;
	ssize_t length;
	int result = -1;

	while ((length = getline(&line, &capacity, file)) != -1) {
		(void)length;
		line_number++;

		if (line_number == 1)
			continue;

		char *columns[8];
		size_t column_count = split_tsv(line, columns, 8);

		if (column_count < 8)
			continue;

		const char *address = columns[1];

		for (size_t column = 6; column <= 7; column++) {
			const char *payload = columns[column];

			if (!*payload || strcmp(payload, "NA") == 0)
				continue;

			const char *field = column == 6 ? "manufacturer_hex" :
							  "service_data_hex";

			size_t index;
			for (index = 0; index < match_count; index++) {
				if (strcmp(matches[index].field, field) == 0 &&
				    strcmp(matches[index].payload, payload) ==
					    0)
					break;
			}

			if (index == match_count) {
				if (match_count >= MAX_PAYLOADS ||
				    strlen(payload) >= PAYLOAD_LEN) {
					fprintf(stderr,
						"Payload limit reached; increase limits if needed.\n");
					goto cleanup;
				}

				PayloadMatch *match = &matches[match_count++];
				snprintf(match->field, sizeof(match->field),
					 "%s", field);
				snprintf(match->payload, sizeof(match->payload),
					 "%s", payload);
			}

			PayloadMatch *match = &matches[index];
			match->observations++;

			if (!address_seen(match, address) &&
			    match->address_count < MAX_DEVICES) {
				snprintf(match->addresses[match->address_count],
					 ADDRESS_LEN, "%s", address);
				match->address_count++;
			}
		}
	}

	if (ferror(file)) {
		perror("Reading observations");
		goto cleanup;
	}

	*matches_out = matches;
	*match_count_out = match_count;
	matches = NULL;
	result = 0;

cleanup:
	free(line);
	free(matches);
	fclose(file);
	return result;
}

static int command_correlate(const char *path)
{
	PayloadMatch *matches = NULL;
	size_t match_count = 0;

	if (load_payload_matches(path, &matches, &match_count) != 0)
		return 1;

	printf("RogueNet — Payload Correlation\n");
	printf("Input: %s\n", path);

	size_t shared_count = 0;

	for (size_t i = 0; i < match_count; i++) {
		PayloadMatch *match = &matches[i];

		if (match->address_count < 2)
			continue;

		shared_count++;
		printf("\n%s: %s\n", match->field, match->payload);
		printf("  Distinct addresses: %zu\n", match->address_count);
		printf("  Total observations: %zu\n", match->observations);
		printf("  Addresses:\n");

		for (size_t j = 0; j < match->address_count; j++)
			printf("    %s\n", match->addresses[j]);
	}

	if (shared_count == 0)
		printf("\nNo exact payloads shared across multiple addresses.\n");
	else
		printf("\nShared payloads found: %zu\n", shared_count);

	printf("Assessment: correlation only; device identity is unconfirmed.\n");

	free(matches);
	return 0;
}

static int load_address_signatures(const char *input_path, const char *address,
				   PayloadSignature signatures[],
				   size_t *signature_count)
{
	FILE *file = fopen(input_path, "r");

	if (file == NULL) {
		perror(input_path);
		return -1;
	}

	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	size_t line_number = 0;
	int found_address = 0;
	int found_payload_columns = 0;
	int result = -1;

	while ((length = getline(&line, &capacity, file)) != -1) {
		(void)length;
		line_number++;

		/* Skip the TSV header. */
		if (line_number == 1)
			continue;

		char *columns[8];
		size_t count = split_tsv(line, columns, 8);

		if (count < 2) {
			fprintf(stderr, "Malformed TSV row %zu in %s\n",
				line_number, input_path);
			goto cleanup;
		}

		if (strcmp(columns[1], address) != 0)
			continue;

		found_address = 1;

		if (count < 8) {
			fprintf(stderr,
				"Payload data unavailable: %s has %zu columns "
				"(expected 8, including manufacturer_hex and "
				"service_data_hex).\n",
				input_path, count);
			goto cleanup;
		}

		found_payload_columns = 1;

		add_payload_values(signatures, signature_count,
				   "manufacturer_hex", columns[6]);
		add_payload_values(signatures, signature_count,
				   "service_data_hex", columns[7]);
	}

	if (ferror(file)) {
		perror(input_path);
		goto cleanup;
	}

	if (!found_address) {
		fprintf(stderr, "Address not found: %s\n", address);
		goto cleanup;
	}

	if (!found_payload_columns) {
		fprintf(stderr, "No payload columns found for %s\n", address);
		goto cleanup;
	}

	result = 0;

cleanup:
	free(line);
	fclose(file);
	return result;
}

static int load_payload_baseline(const char *path,
				 PayloadSignature signatures[],
				 size_t *signature_count)
{
	FILE *file = fopen(path, "r");

	if (file == NULL) {
		perror(path);
		return -1;
	}

	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;

	while ((length = getline(&line, &capacity, file)) != -1) {
		(void)length;

		char *columns[2];
		size_t count = split_tsv(line, columns, 2);

		if (count < 2) {
			continue;
		}

		if (strcmp(columns[0], "manufacturer_hex") != 0 &&
		    strcmp(columns[0], "service_data_hex") != 0) {
			continue;
		}

		add_payload_values(signatures, signature_count, columns[0],
				   columns[1]);
	}

	free(line);

	if (ferror(file)) {
		perror(path);
		fclose(file);
		return -1;
	}

	fclose(file);
	return 0;
}

static int require_min_samples(const char *input_path, const char *address)
{
	Device devices[MAX_DEVICES] = { 0 };
	size_t device_count = 0;

	if (load_observations(input_path, devices, &device_count) != 0)
		return -1;

	Device *device = find_device(devices, device_count, address);

	if (device == NULL) {
		fprintf(stderr, "Address not found: %s\n", address);
		return -1;
	}

	if (device->samples < MIN_SAMPLES) {
		fprintf(stderr,
			"Insufficient observations for %s: "
			"%zu found; at least %d required.\n",
			address, device->samples, MIN_SAMPLES);
		return -1;
	}

	return 0;
}

static int command_payload_baseline(const char *input_path, const char *address,
				    const char *baseline_path)
{
	if (require_min_samples(input_path, address) != 0)
		return 1;

	size_t count = 0;

	if (load_address_signatures(input_path, address, observed_signatures,
				    &count) != 0) {
		return 1;
	}

	if (count == 0) {
		fprintf(stderr, "No payload signatures found for address %s\n",
			address);
		return 1;
	}

	FILE *file = fopen(baseline_path, "w");

	if (file == NULL) {
		perror(baseline_path);
		return 1;
	}

	fprintf(file, "# RogueNet payload baseline v1\n");
	fprintf(file, "# address=%s\n", address);
	fprintf(file, "# field\tpayload\n");

	for (size_t i = 0; i < count; i++) {
		if (fprintf(file, "%s\t%s\n", observed_signatures[i].field,
			    observed_signatures[i].payload) < 0) {
			perror("Writing baseline");
			fclose(file);
			return 1;
		}
	}

	if (fclose(file) != 0) {
		perror(baseline_path);
		return 1;
	}

	printf("Payload baseline created\n");
	printf("Address: %s\n", address);
	printf("Unique payload signatures: %zu\n", count);
	printf("Saved to: %s\n", baseline_path);

	return 0;
}

static int compare_payloads(const char *input_path, const char *address,
			    const char *baseline_path)
{
	if (require_min_samples(input_path, address) != 0)
		return -1;

	size_t baseline_count = 0;
	size_t observed_count = 0;

	if (load_payload_baseline(baseline_path, baseline_signatures,
				  &baseline_count) != 0)
		return -1;

	if (load_address_signatures(input_path, address, observed_signatures,
				    &observed_count) != 0)
		return -1;

	if (baseline_count == 0 || observed_count == 0) {
		fprintf(stderr, "Baseline or current payload set is empty\n");
		return -1;
	}

	size_t new_count = 0;
	size_t missing_count = 0;

	printf("Payload comparison\n");
	printf("Address: %s\n", address);
	printf("Baseline signatures: %zu\n", baseline_count);
	printf("Current signatures: %zu\n\n", observed_count);

	for (size_t i = 0; i < observed_count; i++) {
		if (!signature_exists(baseline_signatures, baseline_count,
				      observed_signatures[i].field,
				      observed_signatures[i].payload)) {
			printf("NEW     %s: %s\n", observed_signatures[i].field,
			       observed_signatures[i].payload);
			new_count++;
		}
	}

	for (size_t i = 0; i < baseline_count; i++) {
		if (!signature_exists(observed_signatures, observed_count,
				      baseline_signatures[i].field,
				      baseline_signatures[i].payload)) {
			printf("MISSING %s: %s\n", baseline_signatures[i].field,
			       baseline_signatures[i].payload);
			missing_count++;
		}
	}

	if (new_count == 0 && missing_count == 0)
		printf("No payload-set differences found.\n");

	printf("\nNew signatures: %zu\n", new_count);
	printf("Missing signatures: %zu\n", missing_count);

	return (new_count > 0 || missing_count > 0) ? 1 : 0;
}

static int command_payload_check(const char *input_path, const char *address,
				 const char *baseline_path)
{
	int result = compare_payloads(input_path, address, baseline_path);

	if (result < 0)
		return 1;

	printf("Assessment: payload differences are not proof "
	       "of impersonation.\n");

	return 0;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s summary <observations.tsv>\n"
		"  %s baseline <observations.tsv> <address> <baseline.tsv>\n"
		"  %s check <observations.tsv> <address> <baseline.tsv> [payload_baseline.tsv]\n"
		"  %s correlate <observations.tsv>\n"
		"  %s payload-baseline <observations.tsv> <address> <baseline.tsv>\n"
		"  %s payload-check <observations.tsv> <address> <baseline.tsv>\n"
		"  %s report <observations.tsv>\n",
		program, program, program, program, program, program, program);
}

int main(int argc, char *argv[])
{
	if (argc >= 2 && strcmp(argv[1], "summary") == 0) {
		if (argc != 3) {
			usage(argv[0]);
			return 1;
		}
		return command_summary(argv[2]);
	}

	if (argc >= 2 && strcmp(argv[1], "report") == 0) {
		if (argc != 3) {
			usage(argv[0]);
			return 1;
		}

		return command_report(argv[2]);
	}

	if (argc >= 2 && strcmp(argv[1], "baseline") == 0) {
		if (argc != 5) {
			usage(argv[0]);
			return 1;
		}
		return command_baseline(argv[2], argv[3], argv[4]);
	}

	if (argc >= 2 && strcmp(argv[1], "check") == 0) {
		if (argc == 5) {
			return command_check(argv[2], argv[3], argv[4], NULL);
		}
		if (argc == 6) {
			return command_check(argv[2], argv[3], argv[4],
					     argv[5]);
		}
		usage(argv[0]);
		return 1;
	}

	if (argc >= 2 && strcmp(argv[1], "correlate") == 0) {
		if (argc != 3) {
			usage(argv[0]);
			return 1;
		}
		return command_correlate(argv[2]);
	}

	if (strcmp(argv[1], "payload-baseline") == 0 && argc == 5) {
		return command_payload_baseline(argv[2], argv[3], argv[4]);
	}

	if (strcmp(argv[1], "payload-check") == 0 && argc == 5) {
		return command_payload_check(argv[2], argv[3], argv[4]);
	}

	usage(argv[0]);
	return 1;
}
