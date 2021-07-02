/*
 * wafreport - ModSecurity summary report utility
 *
 * Copyright (C) 2021 Andrew Howe
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Author: Andrew Howe (https://github.com/RedXanadu/wafreport)
 *
 * Inspired by modsec-positive-stats.rb by Christian Folini (see:
 * https://github.com/Apache-Labor/labor). Designed for systems without access
 * to a Ruby environment
 *
 * This utility prints a table of statistics based on ModSecurity with OWASP CRS
 * inbound and outbound anomaly score totals. The utility expects to receive
 * data on stdin, one request / log entry per line, in the form
 *   INBOUND_ANOMALY_SCORE OUTBOUND_ANOMALY_SCORE
 * e.g.
 *   5 0
 *
 * Usage: Intended to be used with grep, piping in anomaly scores like so:
 *   grep -E -o "[0-9-]+ [0-9-]+$" my_waf.log | ./wafreport
 */

#include <stdio.h>
#include <stdlib.h>

#define MAX_SCORE 65536

int read_in_scores(int *score_count_in, int *score_count_out, int *invalid_in, int *invalid_out);
void print_stats (const int *score_count_in, const int *score_count_out, int invalid_in, int invalid_out, int scores_read);
double avg_mean(const int *score_count_array, int scores_read);
double avg_median(const int *score_count_array, int scores_read);
int digit_width(int n);

int main(void)
{
	int score_count_in[MAX_SCORE+1] = {0},
	    score_count_out[MAX_SCORE+1] = {0}, invalid_in = 0, invalid_out = 0,
	    scores_read = 0;

	scores_read = read_in_scores(score_count_in, score_count_out,
				     &invalid_in, &invalid_out);

	print_stats(score_count_in, score_count_out, invalid_in, invalid_out,
		    scores_read);

	return 0;
}


/******************************************************************************
 * read_in_scores: Reads in lines of anomaly score totals. Stores inbound     *
 *                 score info in an array of int values pointed to by the     *
 *                 first argument, outbound score info in an array pointed to *
 *                 by the second argument, and the number of invalid scores   *
 *                 seen in int values pointed to by the third and fourth      *
 *                 arguments, for inbound and outbound scores, respectively.  *
 *                 Returns the total number of valid score lines read, as an  *
 *                 int value                                                  * 
 ******************************************************************************/
int read_in_scores(int *score_count_in, int *score_count_out, int *invalid_in,
                   int *invalid_out)
{
	int score_in, score_out, count = 0;
	char line_buf[24];

	/* Read in lines continuously, until we get EOF (or a read error) */
	while (fgets(line_buf, sizeof(line_buf), stdin) != NULL) {
		/* Try (the expected) line format: 123 456 */
		if (sscanf(line_buf, "%d%d", &score_in, &score_out) == 2) {
			;

		/* Try line format: 123 - */
		} else if (sscanf(line_buf, "%d", &score_in) == 1) {
			/* No outbound score, so mark it as invalid */
			score_out = -1;

		/* Try line format: - 123 */
		} else if (sscanf(line_buf, "-%d", &score_out) == 1) {
			/* No inbound score, so mark it as invalid */
			score_in = -1;

		/* Still no match? Could not interpret intput line (malformed
		 * input: ignore and don't count it) */
		} else {
			continue;
		}


		/* Store the inbound anomaly score that's been seen */
		if (score_in < 0)
			(*invalid_in)++;
		else if (score_in > MAX_SCORE)
			score_count_in[MAX_SCORE]++;
		else
			score_count_in[score_in]++;

		/* Store the outbound anomaly score that's been seen */
		if (score_out < 0)
			(*invalid_out)++;
		else if (score_out > MAX_SCORE)
			score_count_out[MAX_SCORE]++;
		else
			score_count_out[score_out]++;

		count++;
	}

	return count;
}


/******************************************************************************
 * print_stats: Prints statistics based on arrays of score counts, invalid    *
 *              score counts, and the number of scores read, all of which     *
 *              must be provided as arguments                                 *
 ******************************************************************************/
void print_stats (const int *score_count_in, const int *score_count_out,
                  int invalid_in, int invalid_out, int scores_read)
{
	int i, dig_width_in, dig_width_out, dig_width_scores, running_total;
	double cumulative;


	/* How many digits in the largest inbound score recorded? */
	for (i = MAX_SCORE; i > 0; i--)
		if (score_count_in[i] != 0)
			break;
	dig_width_in = digit_width(i);

	/* How many digits in the largest outbound score recorded? */
	for (i = MAX_SCORE; i > 0; i--)
		if (score_count_out[i] != 0)
			break;
	dig_width_out = digit_width(i);

	/* How many digits in the number of records counted? */
	dig_width_scores = digit_width(scores_read);



	/* Print stats on the inbound requests */
	running_total = invalid_in;
	printf("Inbound (Requests)\n");
	printf("------------------%*s# of req. | %% of req. | Cumulative | Outstanding\n",
		dig_width_in + dig_width_scores + 7, " ");
	printf("%*sTotal number of requests | %d | 100.0000%% | 100.0000%%  |   0.0000%%\n\n",
		dig_width_in + 7, " ",
		scores_read);

	cumulative = 100 * ((double) running_total / scores_read);
	printf("Empty or invalid inbound score %*s| %*d | %8.4f%% | %8.4f%%  | %8.4f%%\n",
		dig_width_in + 1, " ",
		dig_width_scores, invalid_in,
		100 * ((double) invalid_in / scores_read),
		cumulative,
		100 - cumulative);

	/* Print out the non-empty inbound scores from the score count array */
	for (i = 0; i <= MAX_SCORE; i++)
		if (score_count_in[i] != 0) {
			running_total += score_count_in[i];
			cumulative = 100 * ((double) running_total / scores_read);
			printf("Requests with inbound score of %*d | %*d | %8.4f%% | %8.4f%%  | %8.4f%%\n",
				dig_width_in, i,
				dig_width_scores, score_count_in[i],
				100 * ((double) score_count_in[i] / scores_read),
				cumulative,
				100 - cumulative);
		}
	putchar('\n');

	/* Calculate and print averages */
	printf("Mean: %.2f    ", avg_mean(score_count_in, scores_read));
	printf("Median: %.2f\n", avg_median(score_count_in, scores_read));

	putchar('\n');
	putchar('\n');
	putchar('\n');



	/* Print stats on the outbound responses */
	running_total = invalid_out;
	printf("Outbound (Responses)\n");
	printf("--------------------%*s# of res. | %% of res. | Cumulative | Outstanding\n",
		dig_width_out + dig_width_scores + 6, " ");
	printf("%*sTotal number of responses | %d | 100.0000%% | 100.0000%%  |   0.0000%%\n\n",
		dig_width_out + 7, " ",
		scores_read);

	cumulative = 100 * ((double) running_total / scores_read);
	printf("Empty or invalid outbound score %*s| %*d | %8.4f%% | %8.4f%%  | %8.4f%%\n",
		dig_width_out + 1, " ",
		dig_width_scores, invalid_out,
		100 * ((double) invalid_out / scores_read),
		cumulative,
		100 - cumulative);

	/* Print out the non-empty outbound scores from the score count array */
	for (i = 0; i <= MAX_SCORE; i++)
		if (score_count_out[i] != 0) {
			running_total += score_count_out[i];
			cumulative = 100 * ((double) running_total / scores_read);
			printf("Responses with inbound score of %*d | %*d | %8.4f%% | %8.4f%%  | %8.4f%%\n",
				dig_width_out, i,
				dig_width_scores, score_count_out[i],
				100 * ((double) score_count_out[i] / scores_read),
				cumulative,
				100 - cumulative);
		}
	putchar('\n');

	/* Calculate and print averages */
	printf("Mean: %.2f    ", avg_mean(score_count_out, scores_read));
	printf("Median: %.2f\n", avg_median(score_count_out, scores_read));
}


/******************************************************************************
 * avg_mean: Take an array of scores and the number of scores read, and from  *
 *           that calculate and return the mean score                         *
 ******************************************************************************/
double avg_mean(const int *score_count_array, int scores_read)
{
	int i;
	double mean = 0.0;

	for (i = 0; i <= MAX_SCORE; i++)
		mean += i * score_count_array[i];
	mean /= scores_read;

	return mean;
}


/******************************************************************************
 * avg_median: Take an array of scores and the number of scores read, and     *
 *             from that calculate and return the median score                *
 ******************************************************************************/
double avg_median(const int *score_count_array, int scores_read)
{
	int i, lower_value;
	double median = 0.0;

	/* Median: case: odd number of elements */
	if (scores_read % 2) {
		for (i = 0; i <= MAX_SCORE; i++) {
			median += score_count_array[i];
			if (median >= (scores_read + 1) / 2)
				break;
		}
		median = i;
		return median;

	/* Median: case: even number of elements - take an average */
	} else {
		for (i = 0; i <= MAX_SCORE; i++) {
			median += score_count_array[i];
			if (median >= scores_read / 2)
				break;
		}
		lower_value = i;

		median = 0.0;
		for (i = 0; i <= MAX_SCORE; i++) {
			median += score_count_array[i];
			if (median >= (scores_read / 2) + 1)
				break;
		}
		median = (double) (lower_value + i) / 2;
		return median;
	}
}


/******************************************************************************
 * digit_width: Helper function which returns the number of digits required   *
 *              to display a given integer, as an int value                   *
 ******************************************************************************/
int digit_width(int n)
{
	int width = 1;

	/* In case the argument is negative, for some reason, make positive */
	if (n < 0)
		n *= -1;

	while (n > 9) {
		n /= 10;
		width++;
	}

	return width;
}
